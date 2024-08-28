#include <cstddef>
#include <cstdint>
#include <fstream>

#include "envoy/buffer/buffer.h"
#include "envoy/config/tap/v3/common.pb.h"
#include "envoy/data/tap/v3/common.pb.h"
#include "envoy/data/tap/v3/wrapper.pb.h"

#include "source/common/common/thread_impl.h"
#include "source/extensions/common/matcher/matcher.h"
#include "source/extensions/common/tap/tap.h"
#include <list>
#include <memory>
#include <queue>
#include <string>
#include <sys/types.h>
#include "absl/strings/str_format.h"
#include <optional>
#include "source/extensions/common/tap/eric_tap_stats.h"
#include "source/common/api/os_sys_calls_impl.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Tap {

using TraceWrapper = envoy::data::tap::v3::TraceWrapper;

template <class T> class SynchronousCache {

public:
  SynchronousCache(int max_map_size)
      : map_(), notifier_(), mtx_(), max_map_size_(max_map_size), flusher_thread_active_(true){};

  bool enqueue(const unsigned long& trace_id, T&& trace) {
    /*  Check if queue would hit max size, if trace is added to the buffer, if yes
        then dont insert new trace wrapper ptr otw insert it at last
        Procedure :
        The thread that intends to modify the shared variable has to

        acquire a std::mutex (typically via std::lock_guard)
        perform the modification while the lock is held
        execute notify_one or notify_all on the std::condition_variable (the lock does not need to
       be held for notification)

    */
    std::lock_guard<std::mutex> lock(mtx_);
    if (map_.size() < max_map_size_) {
      map_.insert_or_assign(trace_id, std::move(trace));
      notifier_.notify_one();
      return true;
    } else {
      notifier_.notify_one();
      return false;
    }
  }

  std::vector<T> peek() {
    /*
       Wait while condition variable is held by another thread, dont pop any element of buffer
       Procedure :
       Any thread that intends to wait on std::condition_variable has to

       acquire a std::unique_lock<std::mutex>, on the same mutex as used to protect the shared
       variable check the condition, in case it was already updated and notified execute wait,
       wait_for, or wait_until. The wait operations atomically release the mutex and suspend the
       execution of the thread. When the condition variable is notified, a timeout expires, or a
       spurious wakeup occurs, the thread is awakened, and the mutex is atomically reacquired. The
       thread should then check the condition and resume waiting if the wake up was spurious. OR use
       the predicated overload of wait, wait_for, and wait_until, which takes care of the three
       steps above
       */
    /*  O(n) operation but Envoy wouldnt have a large number of open connections */
    std::unique_lock<std::mutex> lock(mtx_);
    while (map_.empty() && flusher_thread_active_) {
      /*
          wait causes the tap_flusher thread to block until the condition variable
          is notified or a spurious wakeup occurs, optionally looping until some predicate
          is satisfied (bool(stop_waiting()) == true).
      */
      notifier_.wait(lock);
    }
    std::vector<T> res;
    if (flusher_thread_active_) {
      for (auto iter = map_.begin(); iter != map_.end(); ++iter) {
        auto tmp = iter->second;
        res.push_back(tmp);
      }

      return res;
    } else {
      return res;
    }
  }

  /* Erase element from map_ in thread safe-way  */
  size_t eraseElement(const unsigned long& trace_id) {
    /*
        Wait while condition variable is held by another thread, dont pop any element of buffer
        Procedure :
        Any thread that intends to wait on std::condition_variable has to

        acquire a std::unique_lock<std::mutex>, on the same mutex as used to protect the shared
       variable check the condition, in case it was already updated and notified execute wait,
       wait_for, or wait_until. The wait operations atomically release the mutex and suspend the
       execution of the thread. When the condition variable is notified, a timeout expires, or a
       spurious wakeup occurs, the thread is awakened, and the mutex is atomically reacquired. The
       thread should then check the condition and resume waiting if the wake up was spurious. OR use
       the predicated overload of wait, wait_for, and wait_until, which takes care of the three
       steps above
        */
    /*  O(n) operation but Envoy wouldnt have a large number of open connections */
    std::unique_lock<std::mutex> lock(mtx_);
    while (map_.empty() && flusher_thread_active_) {
      /*
          wait causes the tap_flusher thread to block until the condition variable
          is notified or a spurious wakeup occurs, optionally looping until some predicate
          is satisfied (bool(stop_waiting()) == true).
      */
      notifier_.wait(lock);
    }
    size_t res = 0;
    if (flusher_thread_active_) {
      for (auto iter = map_.begin(); iter != map_.end();) {
        if (iter->first == trace_id) {
          map_.erase(trace_id);
          res = map_.size();
          break;
        } else {
          ++iter;
        }
      }
      return res;
    } else {
      return res;
    }
  }

  /* Mark the state of the queue and flusher thread associated to it as
     inactive/ready to be destroyed and all resource claring operation that
     needs to be executed :  NOTE if called in ~EricTapSink() then called in
     main thread , if called in*/

  bool destroy() {
    /*  Sequence to initiate destruction of queue and tap flusher
        resources
        Procedure :
        The thread that intends to modify the shared variable has to

        acquire a std::mutex (typically via std::lock_guard)
        perform the modification while the lock is held
        execute notify_one or notify_all on the std::condition_variable (the lock does not need to
       be held for notification)

    */
    std::lock_guard<std::mutex> lock(mtx_);
    flusher_thread_active_ = false;
    // Clear off map to avoid memory leaks in main thread
    // Calling pop() invokes destructor for T before moving to next element
    // An O(queue_size) clearing mechanism for the map
    while (!map_.empty()) {
      map_.clear();
    }
    notifier_.notify_one();
    return true;
  }

  int size() { return map_.size(); }

  // Assignment Constructor
  SynchronousCache(const T& other_cache)
      : map_(other_cache.map_), max_map_size_(other_cache.max_map_size_) {}

  // Move Constructor
  SynchronousCache(T&& other_map) noexcept
      : map_(std::move(other_map.map_)), max_map_size_(other_map.max_map_size_) {}

  // Destructor
  ~SynchronousCache(void) = default;

private:
  std::map<unsigned long, T> map_;
  std::condition_variable notifier_;
  std::mutex mtx_;
  std::size_t max_map_size_;
  // Unhandled flusher thread cleanup and queue cleanups
  // requires active state to be polled in flusher threads so that destructor for
  // EricTapSink can call join on flusher thread
  std::atomic<bool> flusher_thread_active_;
};

template <class T> class SynchronousBuffer {

public:
  // SynchronousBuffer(int max_queue_size , const std::string& hp):
  SynchronousBuffer(int max_queue_size)
      : queue_(), notifier_(), mtx_(), max_queue_size_(max_queue_size),
        flusher_thread_active_(true){};
  /* Check if queue is still active */
  bool isActive() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (flusher_thread_active_) {
      notifier_.notify_one();
      return true;
    } else {
      notifier_.notify_one();
      return false;
    }
  }

  /* Mark the state of the queue and flusher thread associated to it as
     inactive/ready to be destroyed and all resource claring operation that
     needs to be executed :  NOTE if called in ~EricTapSink() then called in
     main thread , if called in*/

  bool destroy() {
    /*  Sequence to initiate destruction of queue and tap flusher
        resources
        Procedure :
        The thread that intends to modify the shared variable has to

        acquire a std::mutex (typically via std::lock_guard)
        perform the modification while the lock is held
        execute notify_one or notify_all on the std::condition_variable (the lock does not need to
       be held for notification)

    */
    std::lock_guard<std::mutex> lock(mtx_);
    flusher_thread_active_ = false;
    // Clear off queue to avoid memory leaks in main thread
    // Calling pop() invokes destructor for T before moving to next element
    // An O(queue_size) clearing mechanism for the queue
    while (!queue_.empty()) {
      queue_.pop();
    }
    notifier_.notify_one();
    return true;
  }
  /* Std FIFO operation push to end of queue */

  bool enqueue(T&& trace) {
    /*  Check if queue would hit max size, if trace is added to the buffer, if yes
        then dont insert new trace wrapper ptr otw insert it at last
        Procedure :
        The thread that intends to modify the shared variable has to

        acquire a std::mutex (typically via std::lock_guard)
        perform the modification while the lock is held
        execute notify_one or notify_all on the std::condition_variable (the lock does not need to
       be held for notification)

    */
    std::lock_guard<std::mutex> lock(mtx_);
    if (queue_.size() < max_queue_size_) {
      queue_.push(std::move(trace));
      notifier_.notify_one();
      return true;
    } else {
      notifier_.notify_one();
      return false;
    }
  }

  /* Get first element of queue and pop it as well */
  T dequeue() {
    /*
    Wait while condition variable is held by another thread, dont pop any element of buffer
    Procedure :
    Any thread that intends to wait on std::condition_variable has to

    acquire a std::unique_lock<std::mutex>, on the same mutex as used to protect the shared variable
    check the condition, in case it was already updated and notified
    execute wait, wait_for, or wait_until. The wait operations atomically release the mutex and
    suspend the execution of the thread. When the condition variable is notified, a timeout expires,
    or a spurious wakeup occurs, the thread is awakened, and the mutex is atomically reacquired. The
    thread should then check the condition and resume waiting if the wake up was spurious. OR use
    the predicated overload of wait, wait_for, and wait_until, which takes care of the three steps
    above
    */
    std::unique_lock<std::mutex> lock(mtx_);
    while (queue_.empty() && flusher_thread_active_) {
      /*
          wait causes the tap_flusher thread to block until the condition variable
          is notified or a spurious wakeup occurs, optionally looping until some predicate
          is satisfied (bool(stop_waiting()) == true).
      */
      notifier_.wait(lock);
    }
    if (flusher_thread_active_) {
      auto res = std::move(queue_.front());
      queue_.pop();
      return res;
    } else {
      return nullptr;
    }
  }

  int size() { return queue_.size(); }

  bool isFull() { return max_queue_size_ == queue_.size(); }

  SynchronousBuffer(std::size_t max_size)
      : queue_(), notifier_(), mtx_(), max_queue_size_(max_size) {}

  // Assignment Constructor
  SynchronousBuffer(const T& other_queue)
      : queue_(other_queue.queue_), max_queue_size_(other_queue.max_queue_size_) {}

  // Move Constructor
  SynchronousBuffer(T&& other_queue) noexcept
      : queue_(std::move(other_queue.queue_)), max_queue_size_(other_queue.max_queue_size_) {}

  // Destructor
  ~SynchronousBuffer(void) = default;

private:
  std::queue<T> queue_;
  std::condition_variable notifier_;
  std::mutex mtx_;
  std::size_t max_queue_size_;
  // std::string host_port_;
  // Unhandled flusher thread cleanup and queue cleanups
  // requires active state to be polled in flusher threads so that destructor for
  // EricTapSink can call join on flusher thread
  std::atomic<bool> flusher_thread_active_;
};

class EricTapSink : public Sink, public Logger::Loggable<Logger::Id::eric_tap> {
public:
  EricTapSink(const envoy::config::tap::v3::StreamingGrpcSink& config, Stats::Scope& scope);
  PerTapSinkHandlePtr
  createPerTapSinkHandle(uint64_t trace_id,
                         envoy::config::tap::v3::OutputSink::OutputSinkTypeCase type) override;
  ~EricTapSink() override;

private:
  friend class EricTapSinkTest;  // to test private classes

  struct EricPerTapSinkHandle : public PerTapSinkHandle {
    EricPerTapSinkHandle(EricTapSink& parent, uint64_t id) : parent_(parent), trace_id_(id){};
    /* submitTrace would be a simple flush to the trace wrapper queue
       The tap_flusher_thread would be responsible for sending trace-wrappers
       to */
    void submitTrace(TraceWrapperPtr&& trace,
                     envoy::config::tap::v3::OutputSink::Format format) override;

    EricTapSink& parent_;
    const uint64_t trace_id_;
  };

  class ConnParams {
  public:
    struct addrinfo addr_info; 
    bool is_ipv4;
    std::string tapcollector_host;
    std::string tapcollector_port;
    /* Duration between two connection when previously existing connection
        got closed and need to reattempt connection */
    uint64_t send_interval;
    /* Maximum duration between two connection attempt when retrying connection */
    uint64_t max_connect_reattempt_interval;
    /* Exponential backoff factor when reattempting connection */
    int exp_backoff_factor;

    const std::string displayConnParamVal() {
      const std::string res =
          absl::StrFormat("IP Version:\'%s\'\nSidecar Host:\'%s\'\
        \nSidecar Port:\'%s\'\nSend Interval:\'%d\'\nConnect Reattempt Interval:\'%d\'\
        \nExponential Backoff factor:\'%d\'",
                          is_ipv4 ? "4" : "6", tapcollector_host, tapcollector_port, send_interval,
                          max_connect_reattempt_interval, exp_backoff_factor);

      return res;
    }

    const std::string displaySkVal(const int& sk) {
      char s[INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN];

      const std::string res = absl::StrFormat(
          "Sidecar Host:\'%s\'\
        \nSidecar Port:\'%s\'\nSocket FD#:\'%d\'\nSidecar resolved Addr:\'%s\'\
        \nSidecar resolved Port:\'%s\'",
          tapcollector_host, tapcollector_port, sk,
          is_ipv4 ? inet_ntop(AF_INET, &(reinterpret_cast<sockaddr_in*>(addr_info.ai_addr)->sin_addr), s, INET_ADDRSTRLEN)
                  : inet_ntop(AF_INET6, &(reinterpret_cast<sockaddr_in6*>(addr_info.ai_addr)->sin6_addr), s, INET6_ADDRSTRLEN),
         tapcollector_port);

      return res;
    }
  };

  class TapFlusherHandler : public Logger::Loggable<Logger::Id::eric_tap> {

  public:
    TapFlusherHandler() : segment_queue_(4096), addr_cache_(4096), os_sys_calls_(Api::OsSysCallsSingleton::get()) {}
    int execute();
    bool setSockOptUtility(int& sockfd);
    bool initConnection(EricTapSink::ConnParams* conn_params,
                                                           int& sock_fd);
    ConnParams conn_params_;
    SynchronousBuffer<TraceWrapperPtr> segment_queue_;
    SynchronousCache<TraceWrapper> addr_cache_;
    bool addr_cache_resend_ = false;
    ~TapFlusherHandler(void) = default;
  private:
    Api::OsSysCallsImpl& os_sys_calls_; // to abstract the sys calls like socket 
  };

  EricTapStats generateStats(Stats::Scope& scope, const std::string& stat_prefix);

  const envoy::config::tap::v3::StreamingGrpcSink config_;
  std::shared_ptr<EricTapStats> stats_;

  /* Resides in main thread */
  // SynchronousBuffer<TraceWrapperPtr> trace_wrapper_queue_ ;
  /* Instantiated from main thread */
  TapFlusherHandler tap_flusher_handler_;
  std::thread tap_flusher_thread_;
  uint32_t max_trace_size_;
};

} // namespace Tap
} // namespace Common
} // namespace Extensions
} // namespace Envoy
