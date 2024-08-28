#include "source/extensions/common/tap/eric_tap_config.h"
#include "eric_tap_stats.h"
#include "source/extensions/common/tap/utility.h"
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <pthread.h>
#include <regex>
#include <string>
#include <thread>

#include "envoy/config/tap/v3/common.pb.h"
#include "envoy/data/tap/v3/transport.pb.h"
#include "external/com_google_protobuf/src/google/protobuf/util/delimited_message_util.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Tap {

/* Executed once in main thread for each listener for every config update
    So regexes could be compiled here if needed */
EricTapSink::EricTapSink(const envoy::config::tap::v3::StreamingGrpcSink& config,
                         Stats::Scope& scope)
    : config_(config), tap_flusher_handler_() {
  ENVOY_LOG(info, "Instantiating Eric-Tap filter");

  // Determine the counter prefixes for the nf_instance name and the group prefix
  std::string stat_prefix = config_.grpc_service().google_grpc().stat_prefix();
  std::string delimiter = "#!_#";
  std::string default_nf_instance_name = "nf-instance";
  std::string default_group_name = "vtap";

  // Find the delimiter between nf_instance name and group name
  auto delimiter_pos = stat_prefix.rfind(delimiter);

  // Extract the nf-instance name prefix from the stat_prefix in the config
  std::string nf_instance_prefix = "";
  if (delimiter_pos != std::string::npos) {
    nf_instance_prefix = stat_prefix.substr(0, delimiter_pos);
    if (nf_instance_prefix.length() < 1) {
      ENVOY_LOG(error,
                "Could not extract an nf-instance name prefix for vTap counters from stat_prefix "
                "\"{}\". Using default nf instance name \"{}\".",
                stat_prefix, default_nf_instance_name);
      nf_instance_prefix = default_nf_instance_name;
    }
  } else {
    ENVOY_LOG(error,
              "Could not find a delimiter \"{}\" to extract an nf-instance name prefix for vTap "
              "counters from stat_prefix \"{}\". Using the full stat_prefix.",
              delimiter, stat_prefix);
    nf_instance_prefix = stat_prefix;
  }

  // Extract the counter group prefix from the stat_prefix in the config
  std::string group_prefix = "";
  if (delimiter_pos != std::string::npos) {
    group_prefix = stat_prefix.substr((delimiter_pos + delimiter.length()),
                                      (stat_prefix.length() - delimiter_pos - delimiter.length()));
    if (group_prefix.length() < 1) {
      ENVOY_LOG(error,
                "Could not extract a group prefix for vTap counters from stat_prefix \"{}\". Using "
                "default group \"{}\".",
                stat_prefix, default_group_name);
      group_prefix = default_group_name;
    }
  } else {
    ENVOY_LOG(error,
              "Could not find a delimiter \"{}\" to extract a group prefix for vTap counters from "
              "stat_prefix \"{}\". Using default group \"{}\".",
              delimiter, stat_prefix, default_group_name);
    group_prefix = default_group_name;
  }

  // make_shared<>() allocates control block for refcounter and  EricTapStats object on
  // heap on a single go
  stats_ = std::make_shared<EricTapStats>(scope, nf_instance_prefix, group_prefix);
  max_trace_size_ = EricUtility::getEnvOrMin("ERIC_TAP_TRACE_SIZE_LIMIT", 65535);
  HostPort hp = EricUtility::getHostPortFromUri(config_.grpc_service().google_grpc().target_uri());

  tap_flusher_handler_.conn_params_.is_ipv4 =
      EricUtility::getEnvOr("IP_FAMILY", "IPv4").compare("IPv4") == 0;
  tap_flusher_handler_.conn_params_.tapcollector_host = hp.host;
  tap_flusher_handler_.conn_params_.tapcollector_port = hp.port;
  tap_flusher_handler_.conn_params_.exp_backoff_factor =
      EricUtility::getEnvOrMin("ERIC_TAP_EXP_BACKOFF", 2);
  tap_flusher_handler_.conn_params_.max_connect_reattempt_interval =
      EricUtility::getEnvOrMin("ERIC_TAP_CONN_REATTEMPT_INTVL", 30);
  tap_flusher_handler_.conn_params_.send_interval =
      EricUtility::getEnvOrMin("ERIC_TAP_SEND_INTVL", 1);
  tap_flusher_thread_ =
      std::thread{&EricTapSink::TapFlusherHandler::execute, &tap_flusher_handler_};
  ENVOY_LOG(debug, "Connection Params:\n{}",
            tap_flusher_handler_.conn_params_.displayConnParamVal());
}

bool EricTapSink::TapFlusherHandler::setSockOptUtility(int& sock_fd) {
  // Common setSockOpt Params
  // DND-32561 Envoy stops sending tap traffic after tapcollector restart
  // Use SO_KEEPALIVE true
  // setsockopt TCP_KEEPIDLE 10
  // setsockopt TCP_KEEPINTVL 5
  // setsockopt TCP_KEEPCNT   3
  int keepcnt = 2;
  int keepidle = 1;
  int keepintvl = 2;
  int keepalive = 1;

  int tcp_user_timeout = 10;
  if (os_sys_calls_.setsockopt(sock_fd, SOL_SOCKET, TCP_USER_TIMEOUT, &tcp_user_timeout, sizeof(int)).return_value_ != 0) {
    ENVOY_LOG(debug, "Error setting setsockopt TCP_USER_TIMEOUT");
    return false;
  }
  if (os_sys_calls_.setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)).return_value_ != 0) {
    ENVOY_LOG(debug, "Error setting setsockopt SO_KEEPALIVE");
    return false;
  }
  if (os_sys_calls_.setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)).return_value_ != 0) {
    ENVOY_LOG(debug, "Error setting setsockopt TCP_KEEPCNT");
    return false;
  }
  if (os_sys_calls_.setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)).return_value_ != 0) {
    ENVOY_LOG(debug, "Error setting setsockopt TCP_KEEPIDLE");
    return false;
  }
  if (os_sys_calls_.setsockopt(sock_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)).return_value_ != 0) {
    ENVOY_LOG(debug, "Error setting setsockopt TCP_KEEPINTVL");
    return false;
  }

  return true;
}

// Create a client socket on tap_flusher thread to
// connect to tapcllector peer

bool
EricTapSink::TapFlusherHandler::initConnection(EricTapSink::ConnParams* conn_params, int& sock_fd) {
  struct addrinfo hints;
  struct addrinfo *result , *rp;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;              /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;          /* TCP Stream */
  hints.ai_flags = 0;
  hints.ai_protocol = IPPROTO_TCP;          /* TCP */
  
  int err = getaddrinfo(conn_params->tapcollector_host.c_str(), conn_params->tapcollector_port.c_str(),&hints,&result);

  if(err != 0) {
    ENVOY_LOG(debug,"Failed on getaddrinfo call:'{}'",sys_errlist[errno]);
    return false;
  }  

  for (rp = result; rp != nullptr; rp = rp->ai_next) {
     conn_params->addr_info = *rp;
     if(rp->ai_family == AF_INET && conn_params->is_ipv4) {
       if ((sock_fd = os_sys_calls_.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP).return_value_) < 0) {
          ENVOY_LOG(debug, "Failed to open client socket , Errno:'{}'", sys_errlist[errno]);
          return false;
        }
        if(!setSockOptUtility(sock_fd)){
          return false;
        }
        break;
     } else if(rp->ai_family == AF_INET6 && !conn_params->is_ipv4) {
        if ((sock_fd = os_sys_calls_.socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP).return_value_) < 0) {
          ENVOY_LOG(debug, "Failed to open client socket , Errno:'{}'", sys_errlist[errno]);
          return false;
        }
        if (!setSockOptUtility(sock_fd))
        {
          return false;
        }
        break;
     }
     
  }
  
  freeaddrinfo(result);                     /* No longer needed */
  return true;
  
}

/* State machine for sending TraceWrapperPtr from the associated SynchronousBuffer */
// TODO(enaidev) Add proper enums for return code and expand visibility of faults

enum EricTapState {
  CONNECTED = 0,
  DISCONNECTED = 1,
};

int EricTapSink::TapFlusherHandler::execute() {
  ENVOY_LOG(debug, "Inside execute() ...");
  EricTapState state = EricTapState::DISCONNECTED;
  int rc = 0;
  int client_sk = 0;
  int conn_attempt = 0;

  uint32_t timeout = 1;

  // Execute the state-machine for sidecar connection
  // and trace flushing while queue is still active and not
  // declared destroyable (which means vtap configuration has
  // been removed )
  while (segment_queue_.isActive()) {

    switch (state) {
    case CONNECTED: {
      timeout = 1;

      char buffer[1];
      int sk_error =  os_sys_calls_.send(client_sk, buffer, sizeof(buffer), MSG_NOSIGNAL).return_value_;
      ENVOY_LOG(trace, "send() call returned:'{}'. client_sk:'{}'", sk_error,client_sk);
      // send() syscall returns number of bytes sent or -1 on error
      // In this case normally 1 is returned by send() on account of 1 byte message in buffer,
      // when sidecar collapses , send() returns -1
      if (sk_error == -1) {
        ENVOY_LOG(
            debug,
            "send() call to sidecar failed, closing current socket and opening new. Errno: '{}'",
            sys_errlist[errno]);
        os_sys_calls_.close(client_sk);
        client_sk = 0;
        state = DISCONNECTED;
        addr_cache_resend_ = true;
        std::this_thread::sleep_for(std::chrono::seconds(conn_params_.send_interval));
      } else {
        // If predicate for address cache resending
        // is enabled then reflect the address_cache elements and
        // send them to tap-collector
        // Also an event that will happen at a much lower frequency
        // so copying is Ok
        // It can happen in one go because even if the sidecar collapses after sending a few
        // connection segments before sending the next event segment it will check the status of TCP
        // connection and resend the connection ifo packets again if required
        if (addr_cache_resend_) {
          auto addr_vector = addr_cache_.peek();
          for (const auto& i : addr_vector) {
            ENVOY_LOG(trace, "Sending connection info segments from address cache. Trace Id '{}'",
                      i.socket_streamed_trace_segment().trace_id());
            // NOTE : SerializeDelimitedToFileDescriptor returns false only if its unable to
            // write the stream to an fd. It takes no notice of the state of underlying TCP
            // connection hence even if tcp connection has terminated is_sent is successful
            google::protobuf::util::SerializeDelimitedToFileDescriptor(i, client_sk);
          }

          addr_cache_resend_ = false;
        }
        // If segement queue is full
        // its possible that there was a missed address_info element in segment queue
        // that is available now in addr_cache which needs to be resent to sidecar to have
        // consistent traces
        if (segment_queue_.isFull()) {
          addr_cache_resend_ = true;
        }
        // TraceWrapperPtr trace_to_send = segment_queue_.dequeue();
        TraceWrapperPtr queue_elem = segment_queue_.dequeue();
        if (queue_elem.get() != nullptr) {
          ENVOY_LOG(trace, "Attempting to send TraceWrapper to tap-collector. Queue size:'{}'",segment_queue_.size());
          // NOTE : SerializeDelimitedToFileDescriptor returns false only if its unable to
          // write the stream to an fd. It takes no notice of the state of underlying TCP connection
          // hence even if tcp connection has terminated is_sent is successful
          const auto& status =
              google::protobuf::util::SerializeDelimitedToFileDescriptor(*queue_elem, client_sk);
          ENVOY_LOG(trace, "Google Protobuf Serialization to FD status ?: '{}'.", status);
        }
      }

    } break;

    case DISCONNECTED: {
      ENVOY_LOG(trace, "Inside state : DISCONNECTED ...");

      conn_attempt += 1;

      if (initConnection(&conn_params_, client_sk)) {

        ENVOY_LOG(trace, "SM Connection Params:\n{}", conn_params_.displaySkVal(client_sk));
      } else {
        ENVOY_LOG(trace, "Connection Params couldn't be initialized, breaking and retrying on "
                         "DISCONNECTED state");
        std::this_thread::sleep_for(std::chrono::seconds(timeout));
        break;
      }
      const auto connect_result = os_sys_calls_
                              .connect(client_sk,conn_params_.addr_info.ai_addr, conn_params_.addr_info.ai_addrlen)
                              .return_value_;
      
      if (connect_result == -1) {
        // Connection attempt was unsuccesful
        timeout *= conn_params_.exp_backoff_factor;
        if (timeout > conn_params_.max_connect_reattempt_interval) {
          timeout = conn_params_.max_connect_reattempt_interval;
        }
        os_sys_calls_.close(client_sk);
        client_sk = 0;
        std::this_thread::sleep_for(std::chrono::seconds(timeout));
      } else {
        state = CONNECTED;
        ENVOY_LOG(trace, "Succesfully connected to tap collector sidecar in #'{}' attempt",
                  conn_attempt);
      }
    } break;
    }
  }
  // Destory the thread return the exit code of the thread For now : 0
  return rc;
}

PerTapSinkHandlePtr
EricTapSink::createPerTapSinkHandle(uint64_t trace_id,
                                    envoy::config::tap::v3::OutputSink::OutputSinkTypeCase type) {
  using ProtoOutputSinkType = envoy::config::tap::v3::OutputSink::OutputSinkTypeCase;
  ASSERT(type == ProtoOutputSinkType::kStreamingGrpc);

  return std::make_unique<EricPerTapSinkHandle>(*this, trace_id);
}

void EricTapSink::EricPerTapSinkHandle::submitTrace(
    TraceWrapperPtr&& trace, envoy::config::tap::v3::OutputSink::Format format) {
  switch (format) {
  case envoy::config::tap::v3::OutputSink::Format::
      OutputSink_Format_PROTO_BINARY_LENGTH_DELIMITED: {
    const auto& is_connection_info = trace->socket_streamed_trace_segment().has_connection();
    const auto& trace_size =
        trace->socket_streamed_trace_segment().has_event()
            ? trace->socket_streamed_trace_segment().event().ByteSizeLong()
            : trace->socket_streamed_trace_segment().connection().ByteSizeLong();
    if (!is_connection_info) {
      if (trace_size < parent_.max_trace_size_) {
        // Determine type of event segment
        const auto event_type =
            trace->socket_streamed_trace_segment().event().event_selector_case();

        if (parent_.tap_flusher_handler_.segment_queue_.enqueue(std::move(trace))) {
          parent_.stats_->ctr_event_segments_tapped_->inc();
          // Step event specific counters
          switch (event_type) {
          case envoy::data::tap::v3::SocketEvent::EventSelectorCase::kRead: {
            parent_.stats_->ctr_event_segments_read_tapped_->inc();
            break;
          }
          case envoy::data::tap::v3::SocketEvent::EventSelectorCase::kWrite: {
            parent_.stats_->ctr_event_segments_write_tapped_->inc();
            break;
          }
          case envoy::data::tap::v3::SocketEvent::EventSelectorCase::kClosed: {
            parent_.stats_->ctr_event_segments_close_tapped_->inc();
            // Clear the connection info entry from the addr_cache_
            const auto& cache_size =
                parent_.tap_flusher_handler_.addr_cache_.eraseElement(trace_id_);
            ENVOY_LOG(debug, "Removed traceID '{}',type:Connection from cache, cache size:'{}'",
                      trace_id_, cache_size);
            break;
          }
          case envoy::data::tap::v3::SocketEvent::EventSelectorCase::EVENT_SELECTOR_NOT_SET:
            break;
          }
        } else {
          parent_.stats_->ctr_event_segments_dropped_->inc();
        }

        const auto& queue_size = parent_.tap_flusher_handler_.segment_queue_.size();
        ENVOY_LOG(debug,
                  "Added traceID '{}',type:Event to queue, queue size: '{}', trace size: '{}'",
                  trace_id_, queue_size, trace_size);
        // TODO: Add queue length counter when counter implementation in flusher thread is available
        // parent_.stats_->gauge_queue_len_->set(queue_size);
      } else {
        parent_.stats_->ctr_event_segment_too_big_->inc();
        ENVOY_LOG(
            debug,
            "Not adding trace '{}' to queue because trace size exceeds '{}' Bytes, trace size:'{}'",
            trace_id_, parent_.max_trace_size_, trace_size);
      }
    } else {
      // Make a copy for address cache , it happens once per connection
      // so its ok
      auto addr_info = *trace;
      // Add to segment Queue
      parent_.tap_flusher_handler_.segment_queue_.enqueue(std::move(trace))
          ? parent_.stats_->ctr_connection_segments_tapped_->inc()
          : parent_.stats_->ctr_connection_segments_dropped_->inc();

      // Get sizes of queue and cache
      const auto& queue_size = parent_.tap_flusher_handler_.segment_queue_.size();

      // Add to Addr Info Cache

      if (parent_.tap_flusher_handler_.addr_cache_.enqueue(trace_id_, std::move(addr_info))) {
        const auto& cache_size = parent_.tap_flusher_handler_.addr_cache_.size();
        ENVOY_LOG(debug,
                  "Added traceID '{}', type Connection to Address Info Cache, Cache Size: '{}'",
                  trace_id_, cache_size);
      } else {
        const auto& cache_size = parent_.tap_flusher_handler_.addr_cache_.size();
        ENVOY_LOG(
            debug,
            "Could not add traceID '{}', type Connection to Address Info Cache, Cache Size: '{}'",
            trace_id_, cache_size);
      }

      // Log
      ENVOY_LOG(debug, "Added traceID '{}',type:Connection to  segment queue, queue size: '{}'",
                trace_id_, queue_size);

      // TODO: Add queue length counter when counter implementation in flusher thread is available
      // parent_.stats_->gauge_queue_len_->set(queue_size);
    }
    break;
  }
  default:
    ENVOY_LOG(debug, "Only PROTO_BINARY_LENGTH_DELIMITED format supported");
  }
}

EricTapSink::~EricTapSink() {
  ENVOY_LOG(info, "Destroying Eric-Tap filter");
  const auto seg_queue_destroy_status = tap_flusher_handler_.segment_queue_.destroy();
  const auto addr_queue_destroy_status = tap_flusher_handler_.addr_cache_.destroy();
  ENVOY_LOG(debug, "Destroyed queue:'{}'", addr_queue_destroy_status);
  ENVOY_LOG(debug, "Destroyed cache:'{}'", seg_queue_destroy_status);
  ENVOY_LOG(debug, "Destroying fusher thread");
  const auto flusher_joinable_status = tap_flusher_thread_.joinable();
  ENVOY_LOG(debug, "Joinable status:'{}'", flusher_joinable_status);
  // Waits for tap_flusher thread to finish
  // before exiting destructor when configuration is released
  // This might take upto conn_params_.max_connect_reattempt_interval
  // seconds to finish as tap_flusher might have been
  // put to sleep because it was in disconnected state
  tap_flusher_thread_.join();
  ENVOY_LOG(info, "Destroyed Eric-Tap filter");
}

} // namespace Tap
} // namespace Common
} // namespace Extensions
} // namespace Envoy
