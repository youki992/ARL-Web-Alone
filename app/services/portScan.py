from app import utils
from app.config import Config
# 导入新的naabu扫描器
from app.services.naabuPortScan import NaabuPortScan

logger = utils.get_logger()


class PortScan:
    """
    端口扫描类 - 使用naabu替代miniscan-port
    保持原有接口兼容性
    """
    def __init__(self, targets, ports=None, service_detect=False, os_detect=False,
                 port_parallelism=None, port_min_rate=None, custom_host_timeout=None, port_scan_type=None):
        """
        初始化端口扫描器
        
        Args:
            targets: 目标IP列表
            ports: 端口范围字符串
            service_detect: 是否进行服务检测
            os_detect: 是否进行操作系统检测
            port_parallelism: 并发数
            port_min_rate: 最小速率
            custom_host_timeout: 自定义超时时间
            port_scan_type: 端口扫描类型 (test, top100, top1000, all, custom)
        """
        # 将targets字符串转换为列表
        if isinstance(targets, str):
            self.targets = targets.split()
        else:
            self.targets = targets
            
        self.ports = ports
        self.service_detect = service_detect
        self.os_detect = os_detect
        self.parallelism = port_parallelism or 32
        self.min_rate = port_min_rate or 64
        self.custom_host_timeout = custom_host_timeout
        self.port_scan_type = port_scan_type
        
        # 创建naabu扫描器实例
        self.scanner = NaabuPortScan(
            targets=self.targets,
            ports=self.ports,
            service_detect=self.service_detect,
            os_detect=self.os_detect,
            port_parallelism=self.parallelism,
            port_min_rate=self.min_rate,
            custom_host_timeout=self.custom_host_timeout,
            port_scan_type=self.port_scan_type
        )

    def run(self):
        """
        执行端口扫描
        
        Returns:
            list: 扫描结果列表
        """
        logger.info("使用naabu进行端口扫描，目标: {}，端口: {}".format(
            str(self.targets)[:50], str(self.ports)[:50]))
        
        return self.scanner.run()

    def os_match_by_accuracy(self, os_match_list):
        """
        根据准确度匹配操作系统信息
        保持与原有接口兼容
        
        Args:
            os_match_list: 操作系统匹配列表
            
        Returns:
            dict: 操作系统信息
        """
        for os_match in os_match_list:
            accuracy = os_match.get('accuracy', '0')
            if int(accuracy) > 90:
                return os_match

        return {}


def port_scan(targets, ports=Config.TOP_10, service_detect=False, os_detect=False,
              port_parallelism=32, port_min_rate=64, custom_host_timeout=None):
    """
    端口扫描函数 - 使用naabu替代miniscan-port
    保持与原有接口的完全兼容性
    
    Args:
        targets: 目标IP列表
        ports: 端口范围，默认为Config.TOP_10
        service_detect: 服务检测（naabu暂不支持）
        os_detect: OS检测（naabu暂不支持）
        port_parallelism: 并发数，默认32
        port_min_rate: 最小速率，默认64
        custom_host_timeout: 自定义超时时间
        
    Returns:
        list: 扫描结果列表，格式与原nmap兼容
    """
    # 过滤目标列表，去重并过滤黑名单IP
    targets = list(set(targets))
    targets = list(filter(utils.not_in_black_ips, targets))
    
    if not targets:
        logger.warning("没有有效的扫描目标")
        return []
    
    # 创建PortScan实例并执行扫描
    ps = PortScan(targets=targets, ports=ports, service_detect=service_detect, os_detect=os_detect,
                  port_parallelism=port_parallelism, port_min_rate=port_min_rate,
                  custom_host_timeout=custom_host_timeout)
    return ps.run()