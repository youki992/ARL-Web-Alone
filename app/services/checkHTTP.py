import time

from app import utils
from .baseThread import BaseThread

import requests.exceptions
logger = utils.get_logger()


class CheckHTTP(BaseThread):
    def __init__(self, urls, concurrency=10):
        super().__init__(urls, concurrency=concurrency)
        self.timeout = (5, 3)
        self.checkout_map = {}

    def check(self, url):
        """
        检查网站是否存活
        只要能获得HTTP响应就认为存活，不过度过滤状态码
        """
        conn = utils.http_req(url, method="get", timeout=self.timeout, stream=True)
        conn.close()

        # 只过滤明确的网络错误状态码，保留大部分响应
        # 502, 504: 网关错误，通常表示后端服务不可用
        # 这些状态码通常表示网络层面的问题，而非应用层响应
        if conn.status_code in [502, 504]:
            return None

        # 构建返回信息
        item = {
            "status": conn.status_code,
            "content-type": conn.headers.get("Content-Type", "")
        }

        return item

    def work(self, url):
        try:
            out = self.check(url)
            if out is not None:
                self.checkout_map[url] = out

        except requests.exceptions.RequestException as e:
            pass

        except Exception as e:
            logger.warning("error on url {}".format(url))
            logger.warning(e)

    def run(self):
        t1 = time.time()
        logger.info("start check http {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        return self.checkout_map


def check_http(urls, concurrency=15):
    c = CheckHTTP(urls, concurrency)
    return c.run()
