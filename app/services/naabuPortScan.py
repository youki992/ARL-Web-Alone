import os
import json
import subprocess
import tempfile
import time
from app import utils
from app.config import Config

logger = utils.get_logger()


class NaabuPortScan:
    """
    使用naabu工具进行端口扫描的类
    替代原有的miniscan-port功能
    
    支持naabu的JSON输出格式和top-ports参数
    """
    
    def __init__(self, targets: list, ports=None, service_detect=False, os_detect=False,
                 port_parallelism=25, port_min_rate=1000, custom_host_timeout=None, port_scan_type=None):
        """
        初始化naabu端口扫描器
        
        Args:
            targets: 目标列表
            ports: 端口配置
            service_detect: 服务检测（naabu暂不支持）
            os_detect: OS检测（naabu暂不支持）
            port_parallelism: 并发数
            port_min_rate: 扫描速率
            custom_host_timeout: 自定义主机超时时间（秒）
            port_scan_type: 端口扫描类型
        """
        self.targets = targets
        self.ports = ports
        self.service_detect = service_detect
        self.os_detect = os_detect
        self.parallelism = port_parallelism
        self.rate = port_min_rate
        self.custom_host_timeout = custom_host_timeout
        self.port_scan_type = port_scan_type
        
        # 获取naabu工具路径
        self.naabu_path = self._get_naabu_path()
        
        # 生成临时文件路径
        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()
        self.target_file = os.path.join(tmp_path, f"naabu_targets_{rand_str}.txt")
        self.result_file = os.path.join(tmp_path, f"naabu_result_{rand_str}.json")

    def _get_naabu_path(self):
        """
        获取naabu工具的路径
        
        Returns:
            str: naabu工具的完整路径
        """
        # 首先尝试从tools目录获取
        tools_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools')
        naabu_path = os.path.join(tools_dir, 'naabu')
        
        # Windows系统添加.exe扩展名
        if os.name == 'nt':
            naabu_path += '.exe'
        
        if os.path.exists(naabu_path):
            logger.debug(f"找到naabu工具: {naabu_path}")
            return naabu_path
        
        # 如果tools目录没有，尝试系统PATH
        try:
            result = subprocess.run(['which', 'naabu'], capture_output=True, text=True)
            if result.returncode == 0:
                system_path = result.stdout.strip()
                logger.debug(f"在系统PATH中找到naabu: {system_path}")
                return system_path
        except:
            pass
        
        # 默认返回naabu，让系统尝试在PATH中查找
        logger.warning("未找到naabu工具，将尝试使用系统PATH")
        return 'naabu'

    def _determine_scan_mode(self, ports_str):
        """
        根据端口字符串确定扫描模式
        
        Args:
            ports_str: 端口字符串
            
        Returns:
            str: 扫描模式 (top100, top1000, all, custom)
        """
        if not ports_str:
            return "top1000"
        
        # 检查是否为预定义的端口列表
        if ports_str == Config.TOP_10:
            return "100"  # naabu的top-ports参数，使用100作为最接近的
        elif ports_str == Config.TOP_100:
            return "100"
        elif ports_str == Config.TOP_1000:
            return "1000"
        elif ports_str == "0-65535":
            return "full"
        else:
            return "custom"

    def _convert_ports_format(self, ports_str):
        """
        将ARL的端口格式转换为naabu支持的格式
        
        Args:
            ports_str: ARL格式的端口字符串，如 "80,443,8080-8090"
            
        Returns:
            str: naabu格式的端口字符串
        """
        if not ports_str:
            return None
        
        # naabu支持的格式与ARL格式兼容，直接返回
        return ports_str

    def run(self):
        """
        执行端口扫描
        
        Returns:
            list: 扫描结果列表，格式与原nmap兼容
        """
        # 批量扫描所有目标
        return self._scan_batch_targets()
    
    def _scan_batch_targets(self):
        """
        批量扫描多个目标，使用临时文件传递目标列表
        
        Returns:
            list: 扫描结果列表
        """
        ip_info_list = []
        
        # 创建临时文件存储目标列表和结果
        temp_target_file = None
        temp_result_file = None
        try:
            logger.info(f"开始批量扫描 {len(self.targets)} 个目标")
            
            # 创建临时目标文件
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                temp_target_file = f.name
                # 将目标写入临时文件，每行一个
                for target in self.targets:
                    f.write(f"{target}\n")
            
            # 创建临时结果文件
            temp_result_file = tempfile.mktemp(suffix='.json')
            
            logger.debug(f"目标文件已创建: {temp_target_file}")
            logger.debug(f"结果文件路径: {temp_result_file}")
            
            # 构建naabu命令
            cmd = [self.naabu_path]
            
            # 使用-l参数指定目标文件
            cmd.extend(['-l', temp_target_file])
            
            # 使用-o参数指定输出文件
            cmd.extend(['-o', temp_result_file])
            
            # 添加-json参数以JSON格式输出
            cmd.extend(['-json'])
            
            # 添加端口参数
            if self.ports:
                scan_mode = self._determine_scan_mode(self.ports)
                logger.debug(f"扫描模式: {scan_mode}, 端口: {self.ports}")
                if scan_mode == "custom":
                    cmd.extend(['-p', self._convert_ports_format(self.ports)])
                else:
                    cmd.extend(['-tp', scan_mode])
            else:
                cmd.extend(['-tp', '1000'])  # 默认扫描top1000端口
                logger.debug("使用默认扫描模式: top1000")
            
            # 添加并发数
            cmd.extend(['-c', str(self.parallelism)])
            
            # 添加速率限制
            cmd.extend(['-rate', str(self.rate)])
            
            # 添加超时参数（如果设置了自定义超时时间）
            if self.custom_host_timeout:
                cmd.extend(['-timeout', f"{self.custom_host_timeout}s"])
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            logger.info(f"扫描参数 - 并发数: {self.parallelism}, 速率: {self.rate}包/秒")
            if self.custom_host_timeout:
                logger.info(f"自定义超时时间: {self.custom_host_timeout}秒")
            
            # 执行扫描
            # 基于端口数和目标数估算超时时间
            scan_mode = self._determine_scan_mode(self.ports) if self.ports else "1000"
            if scan_mode == "custom":
                port_count = self._count_ports(self.ports)
            elif scan_mode == "100":
                port_count = 100
            elif scan_mode == "1000":
                port_count = 1000
            elif scan_mode == "full":
                port_count = 65535
            else:
                port_count = 1000
            
            # 估算超时时间：基于端口数、目标数和速率的更合理计算
            # 基础时间 + (端口数 * 目标数) / 速率 * 安全系数 + 额外缓冲时间
            base_timeout = 180  # 基础超时时间3分钟
            scan_time = (port_count * len(self.targets)) / self.rate
            safety_factor = 5  # 增加安全系数，给予更多时间
            buffer_time = 300  # 额外缓冲时间5分钟
            
            # 对于大量端口或目标，给予更长的超时时间
            if port_count > 1000 or len(self.targets) > 10:
                safety_factor = 8
                buffer_time = 600  # 10分钟缓冲
            
            timeout_seconds = max(600, min(7200, int(base_timeout + scan_time * safety_factor + buffer_time)))
            logger.debug(f"设置总超时时间(估算): {timeout_seconds}秒 (targets={len(self.targets)}, ports={port_count}, rate={self.rate})")
            logger.info(f"预计扫描时间: {int(scan_time)}秒, 总超时时间: {timeout_seconds}秒")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
            
            logger.debug(f"naabu返回码: {result.returncode}")
            logger.debug(f"stdout长度: {len(result.stdout) if result.stdout else 0}")
            logger.debug(f"stderr长度: {len(result.stderr) if result.stderr else 0}")
            
            if result.returncode != 0:
                logger.error(f"naabu批量扫描失败，返回码: {result.returncode}")
                logger.error(f"错误输出: {result.stderr}")
                # 如果批量扫描失败，回退到单个扫描
                logger.info("回退到单个目标扫描模式")
                return self._scan_targets_individually()
            
            # 等待结果文件生成
            max_wait = 10
            wait_count = 0
            while not os.path.exists(temp_result_file) and wait_count < max_wait:
                time.sleep(1)
                wait_count += 1
            
            if not os.path.exists(temp_result_file):
                logger.warning("结果文件未生成，尝试解析stdout输出")
                if result.stdout:
                    return self._parse_naabu_output(result.stdout)
                else:
                    logger.error("没有可解析的输出")
                    return []
            
            # 读取JSON结果文件
            try:
                with open(temp_result_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():
                        logger.info(f"成功读取结果文件，内容长度: {len(content)} 字符")
                        return self._parse_naabu_output(content)
                    else:
                        logger.warning("结果文件为空")
                        return []
            except Exception as e:
                logger.error(f"读取结果文件失败: {str(e)}")
                return []
                
        except subprocess.TimeoutExpired:
            logger.error(f"naabu批量扫描超时 ({timeout_seconds}秒)")
            logger.info("批量扫描超时，尝试回退到单个目标扫描模式")
            # 超时时也尝试回退到单个扫描
            try:
                return self._scan_targets_individually()
            except Exception as fallback_error:
                logger.error(f"单个扫描回退也失败: {str(fallback_error)}")
                return []
        except Exception as e:
            logger.error(f"批量扫描过程中发生错误: {str(e)}")
            import traceback
            logger.debug(f"详细错误信息: {traceback.format_exc()}")
            return []
        finally:
            # 清理临时文件
            if temp_target_file and os.path.exists(temp_target_file):
                try:
                    os.unlink(temp_target_file)
                    logger.debug(f"已删除临时目标文件: {temp_target_file}")
                except:
                    pass
            if temp_result_file and os.path.exists(temp_result_file):
                try:
                    os.unlink(temp_result_file)
                    logger.debug(f"已删除临时结果文件: {temp_result_file}")
                except:
                    pass

    def _scan_targets_individually(self):
        """
        逐个扫描目标（回退方案）
        
        Returns:
            list: 扫描结果列表
        """
        ip_info_list = []
        
        for target in self.targets:
            try:
                result = self._scan_single_target(target)
                if result:
                    ip_info_list.append(result)
            except Exception as e:
                logger.error(f"扫描目标 {target} 时发生错误: {str(e)}")
                continue
        
        return ip_info_list

    def _scan_single_target(self, target):
        """
        扫描单个目标
        
        Args:
            target: 目标IP或域名
            
        Returns:
            dict: 扫描结果
        """
        logger.debug(f"开始扫描单个目标: {target}")
        
        # 创建临时结果文件
        temp_result_file = None
        try:
            temp_result_file = tempfile.mktemp(suffix='.json')
            logger.debug(f"单个目标结果文件路径: {temp_result_file}")
            
            # 构建naabu命令
            cmd = [self.naabu_path, '-host', target]
            
            # 使用-o参数指定输出文件
            cmd.extend(['-o', temp_result_file])
            
            # 添加-json参数以JSON格式输出
            cmd.extend(['-json'])
            
            # 添加端口参数
            if self.ports:
                scan_mode = self._determine_scan_mode(self.ports)
                logger.debug(f"目标 {target} 扫描模式: {scan_mode}, 端口: {self.ports}")
                if scan_mode == "custom":
                    cmd.extend(['-p', self._convert_ports_format(self.ports)])
                else:
                    cmd.extend(['-tp', scan_mode])
            else:
                cmd.extend(['-tp', '1000'])  # 默认扫描模式
                logger.debug(f"目标 {target} 使用默认扫描模式: top1000")
            
            # 添加并发数和速率
            cmd.extend(['-c', str(self.parallelism)])
            cmd.extend(['-rate', str(self.rate)])
            
            # 添加超时参数（如果设置了自定义超时时间）
            if self.custom_host_timeout:
                cmd.extend(['-timeout', f"{self.custom_host_timeout}s"])
            
            logger.debug(f"执行单个目标扫描命令: {' '.join(cmd)}")
            
            # 计算单个目标的合理超时时间
            scan_mode = self._determine_scan_mode(self.ports) if self.ports else "1000"
            if scan_mode == "custom":
                port_count = self._count_ports(self.ports)
            elif scan_mode == "100":
                port_count = 100
            elif scan_mode == "1000":
                port_count = 1000
            elif scan_mode == "full":
                port_count = 65535
            else:
                port_count = 1000
            
            # 单个目标超时时间：基础时间 + 端口数/速率 * 安全系数
            single_timeout = max(300, min(1800, int(120 + (port_count / self.rate) * 5 + 180)))
            logger.debug(f"目标 {target} 设置超时时间: {single_timeout}秒 (端口数: {port_count})")
            
            # 执行扫描
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=single_timeout)
            
            logger.debug(f"目标 {target} naabu返回码: {result.returncode}")
            
            if result.returncode != 0:
                logger.warning(f"目标 {target} 扫描失败，返回码: {result.returncode}")
                logger.debug(f"目标 {target} 错误输出: {result.stderr}")
                return None
            
            # 等待结果文件生成
            max_wait = 5
            wait_count = 0
            while not os.path.exists(temp_result_file) and wait_count < max_wait:
                time.sleep(1)
                wait_count += 1
            
            if not os.path.exists(temp_result_file):
                logger.debug(f"目标 {target} 结果文件未生成，尝试解析stdout")
                if result.stdout:
                    parsed_results = self._parse_naabu_output(result.stdout)
                    if parsed_results:
                        return parsed_results[0]  # 返回第一个结果
                return None
            
            # 读取结果文件
            try:
                with open(temp_result_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content.strip():
                        parsed_results = self._parse_naabu_output(content)
                        if parsed_results:
                            return parsed_results[0]  # 返回第一个结果
                    return None
            except Exception as e:
                logger.error(f"读取目标 {target} 结果文件失败: {str(e)}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.warning(f"目标 {target} 扫描超时")
            return None
        except Exception as e:
            logger.error(f"扫描目标 {target} 时发生错误: {str(e)}")
            return None
        finally:
            # 清理临时文件
            if temp_result_file and os.path.exists(temp_result_file):
                try:
                    os.unlink(temp_result_file)
                except:
                    pass

    def _count_ports(self, ports_str):
        """
        计算端口字符串中的端口数量
        
        Args:
            ports_str: 端口字符串，如 "80,443,8080-8090"
            
        Returns:
            int: 端口数量
        """
        if not ports_str:
            return 0
        
        count = 0
        parts = ports_str.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                # 端口范围
                try:
                    start, end = part.split('-')
                    count += int(end) - int(start) + 1
                except:
                    count += 1  # 解析失败时按1个端口计算
            else:
                # 单个端口
                count += 1
        
        return count

    def _parse_naabu_output(self, output):
        """
        解析naabu的JSON输出
        
        Args:
            output: naabu的JSON输出
            
        Returns:
            list: ARL格式的扫描结果列表
        """
        logger.debug(f"开始解析naabu输出，长度: {len(output)} 字符")
        
        ip_info_dict = {}  # 使用字典按IP分组
        
        try:
            # naabu输出每行一个JSON对象
            lines = output.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # 解析JSON行
                    data = json.loads(line)
                    
                    # 提取信息
                    host = data.get('host', '')
                    ip = data.get('ip', host)  # 如果没有ip字段，使用host
                    port = data.get('port', 0)
                    protocol = data.get('protocol', 'tcp')
                    
                    if not ip or not port:
                        continue
                    
                    # 按IP分组
                    if ip not in ip_info_dict:
                        ip_info_dict[ip] = []
                    
                    # 构建端口信息
                    port_info = {
                        'port_id': int(port),
                        'service_name': '',  # naabu不提供服务名检测
                        'version': '',
                        'product': '',
                        'protocol': protocol
                    }
                    
                    ip_info_dict[ip].append(port_info)
                    
                except json.JSONDecodeError as e:
                    logger.debug(f"跳过无效JSON行: {line[:100]}...")
                    continue
                except Exception as e:
                    logger.debug(f"解析JSON行时发生错误: {str(e)}, 行内容: {line[:100]}...")
                    continue
        
        except Exception as e:
            logger.error(f"解析naabu输出时发生错误: {str(e)}")
            return []
        
        # 构建最终结果
        results = []
        for ip, ports in ip_info_dict.items():
            logger.debug(f"主机 {ip} 有 {len(ports)} 个开放端口")
            
            result = {
                'ip': ip,
                'port_info': ports,
                'os_info': {}  # naabu不提供OS检测
            }
            results.append(result)
        
        logger.debug(f"解析完成，返回 {len(results)} 个主机结果")
        return results


def port_scan(targets, ports=Config.TOP_10, service_detect=False, os_detect=False,
              port_parallelism=25, port_min_rate=1000, custom_host_timeout=None, port_scan_type=None):
    """
    使用naabu进行端口扫描的函数
    保持与原有nmap接口的兼容性
    
    Args:
        targets: 目标IP列表
        ports: 端口范围
        service_detect: 服务检测（naabu不支持）
        os_detect: OS检测（naabu不支持）
        port_parallelism: 并发数
        port_min_rate: 速率限制（包/秒）
        custom_host_timeout: 自定义超时时间
        port_scan_type: 端口扫描类型 (test, top100, top1000, all, custom)
        
    Returns:
        list: 扫描结果列表
    """
    # 过滤目标列表
    targets = list(set(targets))
    targets = list(filter(utils.not_in_black_ips, targets))
    
    if not targets:
        logger.warning("没有有效的扫描目标")
        return []
    
    # 创建扫描器实例
    scanner = NaabuPortScan(
        targets=targets,
        ports=ports,
        service_detect=service_detect,
        os_detect=os_detect,
        port_parallelism=port_parallelism,
        port_min_rate=port_min_rate,
        custom_host_timeout=custom_host_timeout,
        port_scan_type=port_scan_type
    )
    
    # 执行扫描
    return scanner.run()