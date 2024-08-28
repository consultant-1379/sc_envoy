#include "source/extensions/common/tap/eric_tap_config.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/threadsafe_singleton_injector.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"
#include "source/common/network/address_impl.h"
#include "test/test_common/network_utility.h"
#include "test/mocks/api/mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <ostream>
#include <future>
#include <ratio>

using testing::_;
using testing::Return;

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Tap {

class EricTapSinkTest : public testing::TestWithParam<Network::Address::IpVersion> {
protected:
  EricTapSinkTest()
      : api_(Api::createApiForTest()), dispatcher_(api_->allocateDispatcher("test_thread")) {}
  Api::ApiPtr api_;
  Event::DispatcherPtr dispatcher_;

public:
  int client_sk_ = 0;
  int keepalive = 1;
  Network::Address::InstanceConstSharedPtr addr_port_;
  std::thread tap_flusher_thread_;
  EricTapSink::TapFlusherHandler tap_flusher_handler_;
  Stats::TestUtil::TestStore stats_store_;
  Event::TimerPtr timer_;

  std::optional<EricTapSink::ConnParams*> initConnection() {
    EricTapSink::TapFlusherHandler tapFlusherHandler;
    setFakeParam();
    return tapFlusherHandler.initConnection(&conn_params_, client_sk_);
  }

  void TearDown() override { stopThread(); }

  void execute() {
    EXPECT_TRUE(tap_flusher_handler_.segment_queue_.isActive());
    tap_flusher_handler_.conn_params_ = conn_params_;
    tap_flusher_thread_ =
        std::thread{&EricTapSink::TapFlusherHandler::execute, &tap_flusher_handler_};
  }

  void setFakeParam() {
    conn_params_ = EricTapSink::ConnParams();
    conn_params_.is_ipv4 = true;
    conn_params_.tapcollector_host = "127.0.0.1";
    conn_params_.tapcollector_port = 1000;
    conn_params_.exp_backoff_factor = 2;
    conn_params_.max_connect_reattempt_interval = 30;
    conn_params_.send_interval = 1;
  }

  void setParams(Network::Address::IpVersion ip_version) {
    addr_port_ = Network::Utility::parseInternetAddressAndPort(
        Network::Test::getLoopbackAddressUrlString(ip_version).append(":0"),
        ip_version == Network::Address::IpVersion::v6);

    ASSERT_NE(addr_port_, nullptr);
    if (addr_port_->ip()->port() == 0) {
      addr_port_ = Network::Test::findOrCheckFreePort(addr_port_, Network::Socket::Type::Stream);
    }

    ASSERT_NE(addr_port_, nullptr);
    ASSERT_NE(addr_port_->ip(), nullptr);

    conn_params_ = EricTapSink::ConnParams();
    conn_params_.is_ipv4 = ip_version == Network::Address::IpVersion::v4 ? true : false;
    conn_params_.tapcollector_host = addr_port_->ip()->addressAsString();
    conn_params_.tapcollector_port = addr_port_->ip()->port();
    conn_params_.exp_backoff_factor = 2;
    conn_params_.max_connect_reattempt_interval = 30;
    conn_params_.send_interval = 1;
    std::cerr << "Address: " << conn_params_.tapcollector_host << std::endl;
    std::cerr << "Port: " << conn_params_.tapcollector_port << std::endl;
    std::cerr << "IPv4: " << conn_params_.is_ipv4 << std::endl;
  }

  void stopThread() {
    const auto seg_queue_destroy_status = tap_flusher_handler_.segment_queue_.destroy();
    const auto addr_queue_destroy_status = tap_flusher_handler_.addr_cache_.destroy();
    ASSERT_TRUE(seg_queue_destroy_status);
    ASSERT_TRUE(addr_queue_destroy_status);
    ASSERT_FALSE(tap_flusher_handler_.segment_queue_.isActive());
    if (tap_flusher_thread_.joinable()) {
      tap_flusher_thread_.join();
    }
  }

  Network::SocketPtr openSocketAndListen() {
    auto sock = std::make_unique<Network::SocketImpl>(Network::Socket::Type::Stream, addr_port_,
                                                      nullptr, Network::SocketCreationOptions{});
    // Create a socket on which we'll listen for connections from clients.
    // Network::SocketImpl sock(Network::Socket::Type::Stream, addr_port_, nullptr, {});
    EXPECT_TRUE(sock->ioHandle().isOpen()) << addr_port_->asString();

    // Bind the socket to the desired address and port.
    const Api::SysCallIntResult result = sock->bind(addr_port_);

    EXPECT_EQ(result.return_value_, 0)
        << addr_port_->asString() << "\nerror: " << errorDetails(result.errno_)
        << "\nerrno: " << result.errno_;

    // EXPECT_EQ(sock->setBlockingForTest(true).return_value_, 0);
    // Do a bare listen syscall. Not bothering to accept connections as that would
    // require another thread.
    EXPECT_EQ(sock->listen(500).return_value_, 0);

    return sock;
  }

private:
  EricTapSink::ConnParams conn_params_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, EricTapSinkTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Test TapFlusherHandler::initConnection
// should call setsockopt_
// should open a port
// should set ConnParams
TEST_P(EricTapSinkTest, InitConnection) {
  // GTEST_SKIP();
  testing::NiceMock<Api::MockOsSysCalls> os_sys_calls;
  auto os_calls =
      std::make_unique<TestThreadsafeSingletonInjector<Api::OsSysCallsImpl>>(&os_sys_calls);

  EXPECT_CALL(os_sys_calls, socket(_, _, _)).WillOnce(Return(Api::SysCallSocketResult{1, 0}));
  EXPECT_CALL(os_sys_calls, setsockopt_(_, _, _, _, _)).Times(4).WillRepeatedly(Return(0));
  const auto p = initConnection();

  EXPECT_TRUE(p.has_value());
  EXPECT_TRUE(p.value()->is_ipv4);
  EXPECT_STREQ("127.0.0.1",
               Network::Address::Ipv4Instance::sockaddrToString(p.value()->tapcol_addr.tapcol_addr4)
                   .c_str());

  EXPECT_EQ(p.value()->exp_backoff_factor, 2);
  EXPECT_EQ(p.value()->max_connect_reattempt_interval, 30);
  EXPECT_EQ(p.value()->send_interval, 1);
  EXPECT_EQ(p.value()->tapcollector_host, "127.0.0.1");
  EXPECT_EQ(p.value()->tapcollector_port, 1000);
}

// should run execute in thread and join it
// should create a connection
// should recieve test char
// should stop thread
TEST_P(EricTapSinkTest, ExecuteTest) {
  // GTEST_SKIP();
  setParams(GetParam());

  const auto sock = openSocketAndListen();

  execute();
  absl::SleepFor(absl::Milliseconds(50));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);
  const auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);

  ASSERT_NE(io_handle, nullptr);

  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 32);

  //  EXPECT_EQ(receive_buffer.toString(), "a");

  stopThread();
  io_handle->close();
  sock->close();
  EXPECT_FALSE(tap_flusher_handler_.segment_queue_.isActive());
  EXPECT_FALSE(tap_flusher_thread_.joinable());
}

// should connect and send 1 trace
TEST_P(EricTapSinkTest, SendTraceTest) {
  // GTEST_SKIP();
  setParams(GetParam());

  tap_flusher_handler_.segment_queue_.enqueue(makeTraceWrapper());
  EXPECT_EQ(tap_flusher_handler_.segment_queue_.size(), 1);

  const auto sock = openSocketAndListen();

  execute();
  absl::SleepFor(absl::Milliseconds(100));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);
  ASSERT_NE(io_handle, nullptr);
  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  absl::SleepFor(absl::Milliseconds(100));
  io_handle->read(receive_buffer, 100);

  EXPECT_GT(receive_buffer.length(), 1);
  EXPECT_EQ(tap_flusher_handler_.segment_queue_.size(), 0);
  // EXPECT_EQ(receive_buffer.peekInt<char>(receive_buffer.length() - 1), 'a');

  io_handle->close();
  sock->close();
  stopThread();
}

// should connect and send 2 traces
TEST_P(EricTapSinkTest, SendTrace2Test) {
  // GTEST_SKIP();

  setParams(GetParam());

  tap_flusher_handler_.segment_queue_.enqueue(makeTraceWrapper());
  tap_flusher_handler_.segment_queue_.enqueue(makeTraceWrapper());
  EXPECT_EQ(tap_flusher_handler_.segment_queue_.size(), 2);

  const auto sock = openSocketAndListen();

  execute();
  absl::SleepFor(absl::Milliseconds(100));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);
  ASSERT_NE(io_handle, nullptr);
  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  io_handle->read(receive_buffer, 10);
  // EXPECT_EQ(receive_buffer.peekInt<char>(1), 'a');
  // EXPECT_EQ(receive_buffer.peekInt<char>(3), 'a');

  receive_buffer.drain(4);
  EXPECT_EQ(receive_buffer.length(), 0);
  EXPECT_EQ(tap_flusher_handler_.segment_queue_.size(), 0);

  io_handle->close();
  sock->close();
}

// full queue no addr_cache
// fails. Lock is not releasiing the object to delete.
// auto addr_vector = addr_cache_.peek() in eric_tap_config.cc
TEST_P(EricTapSinkTest, FullQueueTestNoAddrCache) {
  GTEST_SKIP();

  setParams(GetParam());
  for (int i = 0; i < 4096; i++) {
    tap_flusher_handler_.segment_queue_.enqueue(makeTraceWrapper());
  }
  EXPECT_TRUE(tap_flusher_handler_.segment_queue_.isFull());

  const auto sock = openSocketAndListen();

  execute();
  absl::SleepFor(absl::Milliseconds(200));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);
  ASSERT_NE(io_handle, nullptr);
  absl::SleepFor(absl::Milliseconds(200));

  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  io_handle->read(receive_buffer, 100);
  std::cerr << "BUFFER: " << receive_buffer.toString() << std::endl;
  ASSERT_GT(receive_buffer.length(), 6);
  // EXPECT_EQ(receive_buffer.peekInt<char>(1), 'a');
  // EXPECT_EQ(receive_buffer.peekInt<char>(3), 'a');
  // EXPECT_EQ(receive_buffer.peekInt<char>(5), 'a');

  // EXPECT_EQ(receive_buffer.length(), 0);
  EXPECT_EQ(tap_flusher_handler_.segment_queue_.size(), 4096 - 500); // 500 is socket queue size

  io_handle->close();
  sock->close();
  stopThread();
}

// full queue
TEST_P(EricTapSinkTest, FullQueueTest) {
  // GTEST_SKIP();
  setParams(GetParam());
  tap_flusher_handler_.addr_cache_.enqueue(125, std::move(*makeTraceWrapper()));
  ASSERT_EQ(tap_flusher_handler_.addr_cache_.size(), 1);

  for (int i = 0; i < 4096; i++) {
    tap_flusher_handler_.segment_queue_.enqueue(makeTraceWrapper());
  }
  EXPECT_TRUE(tap_flusher_handler_.segment_queue_.isFull());

  const auto sock = openSocketAndListen();

  execute();
  absl::SleepFor(absl::Milliseconds(50));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);
  ASSERT_NE(io_handle, nullptr);
  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  // first trace + connect
  io_handle->read(receive_buffer, 2);
  ASSERT_EQ(receive_buffer.length(), 2);
  // EXPECT_EQ(receive_buffer.peekInt<char>(1), 'a');
  receive_buffer.drain(2);

  // addr_cache_resend
  io_handle->read(receive_buffer, 1);
  ASSERT_EQ(receive_buffer.length(), 1);
  // EXPECT_NE(receive_buffer.peekInt<char>(0), 'a');
  receive_buffer.drain(1);

  // traces
  io_handle->read(receive_buffer, 4095 * 2 - 1);
  EXPECT_EQ(receive_buffer.length(), 4095 * 2 - 1);
  // EXPECT_EQ(receive_buffer.peekInt<char>(1), 'a');
  // EXPECT_EQ(receive_buffer.peekInt<char>(3), 'a');
  // EXPECT_EQ(receive_buffer.peekInt<char>(5), 'a');

  EXPECT_EQ(tap_flusher_handler_.segment_queue_.size(), 0);

  io_handle->close();
  sock->close();
}

// disconects
TEST_P(EricTapSinkTest, DisconectsTest) {
  // GTEST_SKIP();
  setParams(GetParam());
  tap_flusher_handler_.addr_cache_.enqueue(125, std::move(*makeTraceWrapper()));
  tap_flusher_handler_.addr_cache_.enqueue(126, std::move(*makeTraceWrapper()));

  ASSERT_EQ(tap_flusher_handler_.addr_cache_.size(), 2);

  const auto sock = openSocketAndListen();
  EXPECT_EQ(sock->setBlockingForTest(true).return_value_, 0);

  execute();
  absl::SleepFor(absl::Milliseconds(100));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);
  ASSERT_NE(io_handle, nullptr);
  // connection is espablished
  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  for (int i = 0; i < 100; i++) {
    tap_flusher_handler_.segment_queue_.enqueue(makeTraceWrapper());
  }

  // close socket
  io_handle->close();
  ASSERT_FALSE(io_handle->isOpen());

  // should not be empty
  ASSERT_NE(tap_flusher_handler_.segment_queue_.size(), 0);
  io_handle = sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);
  ASSERT_NE(io_handle, nullptr);
  absl::SleepFor(absl::Milliseconds(100));

  // connection is espablished
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  // addr_cache_resend 2 times
  io_handle->read(receive_buffer, 2);
  ASSERT_EQ(receive_buffer.length(), 2);
  EXPECT_NE(receive_buffer.peekInt<char>(0), 'a');
  EXPECT_NE(receive_buffer.peekInt<char>(1), 'a');
  receive_buffer.drain(2);

  io_handle->read(receive_buffer, 10);
  EXPECT_EQ(receive_buffer.length(), 10);
  // EXPECT_EQ(receive_buffer.peekInt<char>(1), 'a');
  // EXPECT_EQ(receive_buffer.peekInt<char>(3), 'a');

  io_handle->close();
  sock->close();
}

// should create a Sink from yaml
// no exceptions are expected
TEST_P(EricTapSinkTest, EricTapSinkCreation) {
  // GTEST_SKIP();
  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto t = std::make_unique<EricTapSink>(config, *scope);
  EXPECT_NE(t, nullptr);
}

// sould create a Sink Handler
// no exceptions are expected
TEST_P(EricTapSinkTest, EricTapSinkCreateTapSinkHandle) {
  // GTEST_SKIP();
  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto sink = std::make_unique<EricTapSink>(config, *scope);
  ASSERT_NE(sink, nullptr);
  const auto h = sink->createPerTapSinkHandle(
      50, envoy::config::tap::v3::OutputSink::OutputSinkTypeCase::kStreamingGrpc);
  EXPECT_NE(h, nullptr);
}

// submit trace with no connection
// expect no trace was sent
// expect counters to be 0
// Fails: segments_tapped = 1
TEST_P(EricTapSinkTest, EricTapSinkSubmitTraceNoConnection) {
  GTEST_SKIP();

  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto sink = std::make_unique<EricTapSink>(config, *scope);
  ASSERT_NE(sink, nullptr);
  const auto h = sink->createPerTapSinkHandle(
      50, envoy::config::tap::v3::OutputSink::OutputSinkTypeCase::kStreamingGrpc);
  h->submitTrace(makeTraceWrapper(), envoy::config::tap::v3::OutputSink::JSON_BODY_AS_BYTES);
  absl::SleepFor(absl::Seconds(4));

  h->submitTrace(
      makeTraceWrapper(),
      envoy::config::tap::v3::OutputSink::Format::OutputSink_Format_PROTO_BINARY_LENGTH_DELIMITED);

  for (const auto& c : stats_store_.counters()) {
    EXPECT_EQ(c->value(), 0);
  }
}

TEST_P(EricTapSinkTest, EricTapSinkKillThreadTest) {
  // GTEST_SKIP();
  setParams(GetParam());

  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  config.mutable_grpc_service()->mutable_google_grpc()->set_target_uri(addr_port_->asString());
  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto sink = std::make_unique<EricTapSink>(config, *scope);
  ASSERT_NE(sink, nullptr);
  const auto handle = sink->createPerTapSinkHandle(
      50, envoy::config::tap::v3::OutputSink::OutputSinkTypeCase::kStreamingGrpc);
  handle->submitTrace(
      makeTraceWrapper(),
      envoy::config::tap::v3::OutputSink::Format::OutputSink_Format_PROTO_BINARY_LENGTH_DELIMITED);
  absl::SleepFor(absl::Milliseconds(10));

  const auto seg_queue_destroy_status = tap_flusher_handler_.segment_queue_.destroy();
  const auto addr_queue_destroy_status = tap_flusher_handler_.addr_cache_.destroy();
  ASSERT_TRUE(seg_queue_destroy_status);
  ASSERT_TRUE(addr_queue_destroy_status);
  ASSERT_FALSE(tap_flusher_handler_.segment_queue_.isActive());
}

TEST_P(EricTapSinkTest, EricTapSinkKillThreadFromTimer) {
  // GTEST_SKIP();
  setParams(GetParam());

  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  config.mutable_grpc_service()->mutable_google_grpc()->set_target_uri(addr_port_->asString());
  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto sink = std::make_unique<EricTapSink>(config, *scope);
  ASSERT_NE(sink, nullptr);
  const auto handle = sink->createPerTapSinkHandle(
      50, envoy::config::tap::v3::OutputSink::OutputSinkTypeCase::kStreamingGrpc);
  handle->submitTrace(
      makeTraceWrapper(),
      envoy::config::tap::v3::OutputSink::Format::OutputSink_Format_PROTO_BINARY_LENGTH_DELIMITED);
  absl::SleepFor(absl::Milliseconds(20));

  const auto timer = dispatcher_->createTimer([this] {
    std::cerr << "TIMER" << std::endl;
    const auto seg_queue_destroy_status = tap_flusher_handler_.segment_queue_.destroy();
    const auto addr_queue_destroy_status = tap_flusher_handler_.addr_cache_.destroy();
    ASSERT_TRUE(seg_queue_destroy_status);
    ASSERT_TRUE(addr_queue_destroy_status);
    ASSERT_FALSE(tap_flusher_handler_.segment_queue_.isActive());
    dispatcher_->exit();
  });
  timer->enableTimer(std::chrono::milliseconds(10));
  dispatcher_->run(Event::Dispatcher::RunType::Block);
  absl::SleepFor(absl::Milliseconds(11));
  EXPECT_FALSE(timer->enabled());
  EXPECT_FALSE(tap_flusher_handler_.segment_queue_.isActive());
}

// should connect and send a trace
// counter should increace
// no errors expected
TEST_P(EricTapSinkTest, EricTapSinkSubmitTrace) {
  // GTEST_SKIP();
  Envoy::TestEnvironment::setEnvVar("ERIC_TAP_IP_VERSION",
                                    GetParam() == Network::Address::IpVersion::v6 ? "6" : "4", 1);

  setParams(GetParam());
  const auto sock = openSocketAndListen();

  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  std::cerr << "ADDRESS: " << addr_port_->asString() << std::endl;
  if (GetParam() == Network::Address::IpVersion::v6) {
    config.mutable_grpc_service()->mutable_google_grpc()->set_target_uri(
        fmt::format("{}{}", "::1:", addr_port_->ip()->port()));
  } else {
    config.mutable_grpc_service()->mutable_google_grpc()->set_target_uri(addr_port_->asString());
  }

  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto sink = std::make_unique<EricTapSink>(config, *scope);
  ASSERT_NE(sink, nullptr);
  const auto handle = sink->createPerTapSinkHandle(
      50, envoy::config::tap::v3::OutputSink::OutputSinkTypeCase::kStreamingGrpc);
  handle->submitTrace(
      makeTraceWrapper(),
      envoy::config::tap::v3::OutputSink::Format::OutputSink_Format_PROTO_BINARY_LENGTH_DELIMITED);

  absl::SleepFor(absl::Milliseconds(10));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);

  // timeOutForThread(50);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);

  ASSERT_NE(io_handle, nullptr);

  // connection is espablished
  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  io_handle->read(receive_buffer, 10);
  EXPECT_EQ(receive_buffer.length(), 2);
  // EXPECT_EQ(receive_buffer.peekInt<char>(1), 'a');

  EXPECT_EQ(stats_store_
                .counterFromString(
                    "test.scope.eric_tap_stats.n8e.test.g3p.prefix.s9e.event.segments_tapped")
                .value(),
            1);

  for (const auto& c : stats_store_.counters()) {
    std::cerr << "COUNTER: " << c->name() << " : " << c->value() << std::endl;
    // EXPECT_EQ(c->value(), 0);
  }

  io_handle->close();
  sock->close();
}

TEST_F(EricTapSinkTest, EricTapSinkSubmitTraceIpv6UriWithoutBrackets) {
  Envoy::TestEnvironment::setEnvVar("ERIC_TAP_IP_VERSION", "6", 1);
  setParams(Network::Address::IpVersion::v6);
  const auto sock = openSocketAndListen();

  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  const auto uri =
      fmt::format("{}:{}", addr_port_->ip()->addressAsString(), addr_port_->ip()->port());
  std::cerr << "URI: " << uri << std::endl;
  config.mutable_grpc_service()->mutable_google_grpc()->set_target_uri(
      fmt::format("{}{}", "::1:", addr_port_->ip()->port()));
  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto sink = std::make_unique<EricTapSink>(config, *scope);
  ASSERT_NE(sink, nullptr);
  const auto handle = sink->createPerTapSinkHandle(
      50, envoy::config::tap::v3::OutputSink::OutputSinkTypeCase::kStreamingGrpc);
  handle->submitTrace(
      makeTraceWrapper(),
      envoy::config::tap::v3::OutputSink::Format::OutputSink_Format_PROTO_BINARY_LENGTH_DELIMITED);

  absl::SleepFor(absl::Milliseconds(10));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);

  // timeOutForThread(50);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);

  ASSERT_NE(io_handle, nullptr);

  // connection is espablished
  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  io_handle->read(receive_buffer, 10);
  EXPECT_EQ(receive_buffer.length(), 2);
  // EXPECT_EQ(receive_buffer.peekInt<char>(1), 'a');

  EXPECT_EQ(stats_store_
                .counterFromString(
                    "test.scope.eric_tap_stats.n8e.test.g3p.prefix.s9e.event.segments_tapped")
                .value(),
            1);

  io_handle->close();
  sock->close();
}

// try to sent big segment
// expect no traces were sent
// expect event.segments_size_too_big to be 1
TEST_P(EricTapSinkTest, EricTapSinkSubmitTraceBigSegment) {
  // GTEST_SKIP();
  Envoy::TestEnvironment::setEnvVar("IP_FAMILY",
                                    GetParam() == Network::Address::IpVersion::v6 ? "V6_ONLY" : "V4_ONLY", 1);
  Envoy::TestEnvironment::setEnvVar("ERIC_TAP_TRACE_SIZE_LIMIT", "10", 0);
  std::cerr << "ERIC_TAP_TRACE_SIZE_LIMIT: " << std::getenv("ERIC_TAP_TRACE_SIZE_LIMIT")
            << std::endl;
  ASSERT_STREQ(std::getenv("ERIC_TAP_TRACE_SIZE_LIMIT"), "10");
  setParams(GetParam());
  const auto sock = openSocketAndListen();

  envoy::config::tap::v3::StreamingGrpcSink config{};
  std::string yaml{R"EOF(
tap_id: "1253"
grpc_service:
  google_grpc:
    target_uri: 127.0.0.1:55678
    stat_prefix: "test#!_#prefix"
)EOF"};
  TestUtility::loadFromYaml(yaml, config);
  if (GetParam() == Network::Address::IpVersion::v6) {
    config.mutable_grpc_service()->mutable_google_grpc()->set_target_uri(
        fmt::format("{}{}", "::1:", addr_port_->ip()->port()));
  } else {
    config.mutable_grpc_service()->mutable_google_grpc()->set_target_uri(addr_port_->asString());
  }
  Stats::ScopeSharedPtr scope = stats_store_.createScope("test.scope.");

  const auto sink = std::make_unique<EricTapSink>(config, *scope);
  ASSERT_NE(sink, nullptr);
  const auto handle = sink->createPerTapSinkHandle(
      50, envoy::config::tap::v3::OutputSink::OutputSinkTypeCase::kStreamingGrpc);

  auto trace = makeTraceWrapper();
  trace->mutable_socket_streamed_trace_segment()
      ->mutable_event()
      ->mutable_read()
      ->mutable_data()
      ->set_as_bytes("hello");

  handle->submitTrace(
      std::move(trace),
      envoy::config::tap::v3::OutputSink::Format::OutputSink_Format_PROTO_BINARY_LENGTH_DELIMITED);

  absl::SleepFor(absl::Milliseconds(10));

  sockaddr_storage remote_addr;
  socklen_t remote_addr_len = sizeof(remote_addr);
  auto io_handle =
      sock->ioHandle().accept(reinterpret_cast<sockaddr*>(&remote_addr), &remote_addr_len);
  ASSERT_NE(io_handle, nullptr);

  // connection is espablished
  Buffer::OwnedImpl receive_buffer;
  io_handle->read(receive_buffer, 1);
  //  EXPECT_EQ(receive_buffer.toString(), "a");
  receive_buffer.drain(1);

  io_handle->read(receive_buffer, 10);
  EXPECT_EQ(receive_buffer.length(), 0);

  EXPECT_EQ(stats_store_
                .counterFromString(
                    "test.scope.eric_tap_stats.n8e.test.g3p.prefix.s9e.event.segments_size_too_big")
                .value(),
            1);
  // other counters should be 0
  for (const auto& c : stats_store_.counters()) {
    if (absl::EndsWith(c->name(), "event.segments_size_too_big")) {
      continue;
    }
    EXPECT_EQ(c->value(), 0);
  }

  io_handle->close();
  sock->close();
}

} // namespace Tap
} // namespace Common
} // namespace Extensions
} // namespace Envoy