import time
from app import utils
from .baseThread import BaseThread
logger = utils.get_logger()


class ProbeHTTP(BaseThread):
    def __init__(self, domains, concurrency=6):
        super().__init__(self._build_targets(domains), concurrency = concurrency)

        self.sites = []
        self.domains = domains

    def _build_targets(self, domains):
        _targets = []
        for item in domains:
            domain = item
            if hasattr(item, 'domain'):
                domain = item.domain

            _targets.append("https://{}".format(domain))
            _targets.append("http://{}".format(domain))

        return _targets

    def work(self, target):
        """
        检查域名是否存活
        只要能获得HTTP响应就认为存活，不过度过滤状态码
        """
        conn = utils.http_req(target, 'get', timeout=(3, 2), stream=True)
        conn.close()

        # 只过滤明确的网络错误状态码，保留大部分响应
        # 502, 504: 网关错误，通常表示后端服务不可用
        if conn.status_code in [502, 504]:
            logger.debug(f"{target} 状态码为 {conn.status_code} 跳过")
            return

        self.sites.append(target)

    def run(self):
        t1 = time.time()
        logger.info("start ProbeHTTP {}".format(len(self.targets)))
        self._run()
        # 去除https和http相同的
        alive_site = []
        for x in self.sites:
            if x.startswith("https://"):
                alive_site.append(x)

            elif x.startswith("http://"):
                x_temp = "https://" + x[7:]
                if x_temp not in self.sites:
                    alive_site.append(x)

        elapse = time.time() - t1
        logger.info("end ProbeHTTP {} elapse {}".format(len(alive_site), elapse))

        return alive_site


def probe_http(domain, concurrency=10):
    p = ProbeHTTP(domain, concurrency=concurrency)
    return p.run()
