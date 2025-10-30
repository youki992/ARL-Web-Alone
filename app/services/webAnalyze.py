import time
import json
from app import utils
from app.config import Config
from .baseThread import BaseThread
logger = utils.get_logger()


class WebAnalyze(BaseThread):
    def __init__(self, sites, concurrency=3):
        super().__init__(sites, concurrency = concurrency)
        self.analyze_map = {}

    def work(self, site):
        """
        分析网站的技术栈信息
        
        Args:
            site (str): 要分析的网站URL
        """
        cmd_parameters = [Config.PHANTOMJS_BIN,
                          '--ignore-ssl-errors=true',
                          '--ssl-protocol=any',
                          '--ssl-ciphers=ALL',
                          Config.DRIVER_JS ,
                          site
                          ]
        logger.debug("WebAnalyze=> {}".format(" ".join(cmd_parameters)))

        try:
            output = utils.check_output(cmd_parameters, timeout=20)
            output = output.decode('utf-8').strip()
            
            # 记录原始输出用于调试
            logger.debug("PhantomJS output for {}: {}".format(site, output))
            
            # 检查输出是否为空
            if not output:
                logger.warning("PhantomJS returned empty output for {}".format(site))
                self.analyze_map[site] = []
                return
            
            # 尝试解析JSON
            try:
                json_data = json.loads(output)
                if isinstance(json_data, dict) and "applications" in json_data:
                    self.analyze_map[site] = json_data["applications"]
                else:
                    logger.warning("Invalid JSON structure for {}: missing 'applications' field".format(site))
                    self.analyze_map[site] = []
            except json.JSONDecodeError as e:
                logger.error("JSON decode error for {}: {}. Raw output: {}".format(site, str(e), repr(output)))
                self.analyze_map[site] = []
                
        except Exception as e:
            logger.error("PhantomJS execution failed for {}: {}".format(site, str(e)))
            self.analyze_map[site] = []

    def run(self):
        t1 = time.time()
        logger.info("start WebAnalyze {}".format(len(self.targets)))
        self._run()
        elapse = time.time() - t1
        logger.info("end WebAnalyze elapse {}".format(elapse))
        return self.analyze_map


def web_analyze(sites, concurrency=3):
    s = WebAnalyze(sites, concurrency=concurrency)
    return s.run()





