/* XMRig Remote Backend (experimental)
 * Minimal scaffold to integrate a remote device backend. Disabled by default.
 */
#ifndef XMRIG_REMOTEBACKEND_H
#define XMRIG_REMOTEBACKEND_H

#include "backend/common/interfaces/IBackend.h"
#include "base/tools/Object.h"
#include "base/tools/String.h"

namespace xmrig {

class Controller;
class RemoteBackendPrivate;

class RemoteBackend : public IBackend {
public:
    XMRIG_DISABLE_COPY_MOVE_DEFAULT(RemoteBackend)

    explicit RemoteBackend(Controller *controller);
    ~RemoteBackend() override;

protected:
    inline void execCommand(char) override {}

    bool isEnabled() const override;
    bool isEnabled(const Algorithm &algorithm) const override;
    bool tick(uint64_t ticks) override;
    const Hashrate *hashrate() const override;
    const String &profileName() const override;
    const String &type() const override;
    void prepare(const Job &nextJob) override;
    void printHashrate(bool details) override;
    void printHealth() override;
    void setJob(const Job &job) override;
    void start(IWorker *worker, bool ready) override;
    void stop() override;

#ifdef XMRIG_FEATURE_API
    rapidjson::Value toJSON(rapidjson::Document &doc) const override;
    void handleRequest(IApiRequest &request) override;
#endif

#ifdef XMRIG_FEATURE_BENCHMARK
    Benchmark *benchmark() const override { return nullptr; }
    void printBenchProgress() const override {}
#endif

private:
    RemoteBackendPrivate *d_ptr;
};

} // namespace xmrig

#endif // XMRIG_REMOTEBACKEND_H
