import os
import json
import subprocess
import tempfile
import re
from app import utils
from app.config import Config

logger = utils.get_logger()


class MiniscanPortScan:
    """
    使用miniscan-port工具进行端口扫描的类
    替代原有的nmap扫描功能
    
    支持新的miniscan-port输出格式，包含ASCII艺术字和进度信息
    """
    
    def __init__(self, targets, ports=None, service_detect=False, os_detect=False,
                 port_parallelism=None, port_min_rate=None, custom_host_timeout=None, port_scan_type=None):
        """
        初始化MiniscanPortScan扫描器
        
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
        self.targets = targets
        self.ports = ports
        self.service_detect = service_detect
        self.os_detect = os_detect
        self.parallelism = port_parallelism or 100  # miniscan-port默认100线程
        self.timeout = custom_host_timeout or 1  # miniscan-port默认3秒超时
        self.port_scan_type = port_scan_type  # 新增：端口扫描类型
        
        # 获取miniscan-port工具路径
        self.miniscan_path = self._get_miniscan_path()
        
    def _get_miniscan_path(self):
        """
        获取miniscan-port工具的路径
        
        Returns:
            str: miniscan-port工具的完整路径
        """
        # 获取当前脚本所在目录的tools文件夹
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        tools_dir = os.path.join(current_dir, 'tools')
        
        # 优先查找重命名后的文件 miniscan-port
        miniscan_exe = os.path.join(tools_dir, 'miniscan-port')
        
        if os.path.exists(miniscan_exe):
            return miniscan_exe
        
        # 如果找不到，尝试查找原始文件名
        if os.name == 'nt':  # Windows
            miniscan_exe = os.path.join(tools_dir, 'miniscan-port.exe')
        else:  # Linux/Unix
            miniscan_exe = os.path.join(tools_dir, 'miniscan-port-ubuntu-amd64')
        
        if os.path.exists(miniscan_exe):
            return miniscan_exe
        
        # 最后尝试在miniscan-port子目录中查找
        if os.name == 'nt':
            miniscan_exe = os.path.join(tools_dir, 'miniscan-port', 'miniscan-port.exe')
        else:
            miniscan_exe = os.path.join(tools_dir, 'miniscan-port', 'miniscan-port-ubuntu-amd64')
        
        return miniscan_exe
    
    def _convert_ports_format(self, ports_str):
        """
        将ARL的端口格式转换为miniscan-port支持的格式
        
        Args:
            ports_str: ARL格式的端口字符串，如 "80,443,8080-8090"
            
        Returns:
            str: miniscan-port格式的端口字符串
        """
        if not ports_str:
            return None
            
        # miniscan-port支持的格式与nmap类似，直接返回
        return ports_str
    
    def _determine_scan_mode(self, ports_str):
        """
        根据前端配置的port_scan_type确定扫描模式
        
        Args:
            ports_str: 端口字符串（用于自定义模式）
            
        Returns:
            str: 扫描模式 (top100, top1000, all, custom)
        """
        # 若显式提供了端口字符串，则优先按端口字符串决定
        if ports_str:
            normalized = ports_str.strip().lower()
            if normalized in ("top100", "top1000", "all"):
                return normalized
            if normalized == "0-65535":
                return "all"
            # 任意显式端口列表或范围都视为自定义
            return "custom"
        
        # 其次考虑 port_scan_type 配置
        if self.port_scan_type:
            if self.port_scan_type == "test":
                return "top100"
            elif self.port_scan_type in ("top100", "top1000", "all", "custom"):
                return self.port_scan_type
        
        # 默认模式
        return "top1000"
    
    def _count_ports(self, ports_str):
        """
        计算端口字符串中包含的端口数量
        
        Args:
            ports_str: 端口字符串
            
        Returns:
            int: 端口数量
        """
        if not ports_str:
            return 0
            
        count = 0
        for part in ports_str.split(','):
            if '-' in part:
                start, end = part.split('-')
                count += int(end) - int(start) + 1
            else:
                count += 1
        return count
    
    def run(self):
        """
        执行端口扫描
        
        Returns:
            list: 扫描结果列表，格式与原nmap兼容
        """
        # 始终一次性批量扫描所有目标
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
            
            # 构建miniscan-port命令
            cmd = [self.miniscan_path]
            
            # 使用-t参数指定目标文件
            cmd.extend(['-t', temp_target_file])
            
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
                    cmd.extend(['-m', scan_mode])
            else:
                cmd.extend(['-m', 'top1000'])  # 默认扫描模式
                logger.debug("使用默认扫描模式: top1000")
            
            # 添加线程数 - 增加并发数以提高速度
            parallelism = min(self.parallelism, 100)
            cmd.extend(['-T', str(parallelism)])
            
            # 添加超时时间 - 使用用户指定的超时时间
            timeout = self.timeout
            cmd.extend(['--timeout', str(timeout)])
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            logger.info(f"扫描参数 - 并发数: {parallelism}, 超时: {timeout}秒")
            
            # 执行扫描
            # 原超时时间: len(self.targets) * 60
            # 基于端口数、并发与每端口超时动态估算总超时时间
            if self.ports:
                _mode = self._determine_scan_mode(self.ports)
                if _mode == "custom":
                    _port_count = self._count_ports(self.ports)
                elif _mode == "top100":
                    _port_count = 100
                elif _mode == "top1000":
                    _port_count = 1000
                elif _mode == "all":
                    _port_count = 65535
                else:
                    _port_count = 1000
            else:
                _port_count = 1000
            timeout_seconds = max(60, min(1800, int((_port_count * len(self.targets)) / max(1, parallelism) * (self.timeout + 2))))
            logger.debug(f"设置总超时时间(估算): {timeout_seconds}秒 (targets={len(self.targets)}, ports={_port_count}, T={parallelism}, perPortTimeout={self.timeout})")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
            
            logger.debug(f"miniscan-port返回码: {result.returncode}")
            logger.debug(f"stdout长度: {len(result.stdout) if result.stdout else 0}")
            logger.debug(f"stderr长度: {len(result.stderr) if result.stderr else 0}")
            
            if result.returncode != 0:
                logger.error(f"miniscan-port批量扫描失败，返回码: {result.returncode}")
                logger.error(f"错误输出: {result.stderr}")
                # 如果批量扫描失败，回退到单个扫描
                logger.info("回退到单个目标扫描模式")
                return self._scan_targets_individually()
            
            # 检查JSON结果文件是否存在
            json_result_file = temp_result_file
            # 等待文件生成，最多 3 秒
            if not os.path.exists(json_result_file):
                import time
                for _ in range(30):
                    if os.path.exists(json_result_file):
                        break
                    time.sleep(0.1)
            # 兼容老逻辑：如果仍不存在，尝试 temp_result_file + '.json'
            if not os.path.exists(json_result_file) and os.path.exists(temp_result_file + '.json'):
                logger.warning(f"JSON结果文件未找到，使用兼容路径: {temp_result_file + '.json'}")
                json_result_file = temp_result_file + '.json'
            if not os.path.exists(json_result_file):
                logger.warning(f"JSON结果文件不存在: {json_result_file}")
                logger.info("回退到单个目标扫描模式")
                return self._scan_targets_individually()
            
            logger.info(f"批量扫描完成，开始解析JSON文件: {json_result_file}")
            
            # 从JSON文件读取结果
            parsed_results = self._parse_json_file(json_result_file)
            logger.info(f"解析完成，获得 {len(parsed_results)} 个结果")
            
            return parsed_results
            
        except subprocess.TimeoutExpired:
            logger.error(f"批量扫描超时（{timeout_seconds}秒），回退到单个扫描")
            return self._scan_targets_individually()
        except Exception as e:
            logger.error(f"批量扫描时发生错误: {str(e)}，回退到单个扫描")
            import traceback
            logger.debug(f"详细错误信息: {traceback.format_exc()}")
            return self._scan_targets_individually()
        finally:
            # 清理临时文件
            if temp_target_file and os.path.exists(temp_target_file):
                try:
                    os.unlink(temp_target_file)
                    logger.debug(f"临时目标文件已清理: {temp_target_file}")
                except Exception as e:
                    logger.warning(f"清理临时目标文件失败: {e}")
            
            if temp_result_file:
                # 仅清理实际生成的结果文件
                if os.path.exists(temp_result_file):
                    try:
                        os.unlink(temp_result_file)
                        logger.debug(f"临时结果文件已清理: {temp_result_file}")
                    except Exception as e:
                        logger.warning(f"清理临时结果文件失败: {e}")
            
            # 已改为仅清理实际生成的结果文件，避免误拼接'.json'
            # 此处无需再次清理
    
    def _scan_targets_in_batches(self):
        """
        分批扫描大量目标
        
        Returns:
            list: 扫描结果列表
        """
        ip_info_list = []
        batch_size = 5  # 每批扫描5个目标
        
        for i in range(0, len(self.targets), batch_size):
            batch_targets = self.targets[i:i + batch_size]
            
            # 创建临时扫描器处理这一批
            batch_scanner = MiniscanPortScan(
                targets=batch_targets,
                ports=self.ports,
                service_detect=self.service_detect,
                os_detect=self.os_detect,
                port_parallelism=self.parallelism,
                custom_host_timeout=self.timeout
            )
            
            batch_results = batch_scanner._scan_batch_targets()
            if batch_results:
                ip_info_list.extend(batch_results)
        
        return ip_info_list
    
    def _scan_targets_individually(self):
        """
        逐个扫描目标（回退方案）
        
        Returns:
            list: 扫描结果列表
        """
        ip_info_list = []
        
        logger.info(f"开始逐个扫描 {len(self.targets)} 个目标")
        
        for i, target in enumerate(self.targets, 1):
            try:
                logger.debug(f"扫描目标 {i}/{len(self.targets)}: {target}")
                result = self._scan_single_target(target)
                if result:
                    ip_info_list.append(result)
                    logger.debug(f"目标 {target} 扫描成功，发现 {len(result.get('port_info', []))} 个开放端口")
                else:
                    logger.debug(f"目标 {target} 扫描完成，无开放端口")
            except Exception as e:
                logger.error(f"扫描目标 {target} 时发生错误: {str(e)}")
                import traceback
                logger.debug(f"详细错误信息: {traceback.format_exc()}")
                continue
        
        logger.info(f"逐个扫描完成，共获得 {len(ip_info_list)} 个有效结果")
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
            
            # 构建miniscan-port命令
            cmd = [self.miniscan_path, '-t', target]
            
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
                    cmd.extend(['-m', scan_mode])
            else:
                cmd.extend(['-m', 'top1000'])  # 默认扫描模式
                logger.debug(f"目标 {target} 使用默认扫描模式: top1000")
            
            # 添加线程数
            cmd.extend(['-T', str(self.parallelism)])
            
            # 添加超时时间
            cmd.extend(['--timeout', str(self.timeout)])
            
            logger.debug(f"目标 {target} 执行命令: {' '.join(cmd)}")
            
            # 执行命令（动态估算超时时间）
            if self.ports:
                _mode = self._determine_scan_mode(self.ports)
                if _mode == "custom":
                    _port_count = self._count_ports(self.ports)
                elif _mode == "top100":
                    _port_count = 100
                elif _mode == "top1000":
                    _port_count = 1000
                elif _mode == "all":
                    _port_count = 65535
                else:
                    _port_count = 1000
            else:
                _port_count = 1000
            _timeout_seconds = max(30, min(900, int((_port_count) / max(1, self.parallelism) * (self.timeout + 2))))
            logger.debug(f"目标 {target} 设置超时时间(估算): {_timeout_seconds}秒 (ports={_port_count}, T={self.parallelism}, perPortTimeout={self.timeout})")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=_timeout_seconds)
            
            logger.debug(f"目标 {target} 命令返回码: {result.returncode}")
            logger.debug(f"目标 {target} stdout长度: {len(result.stdout) if result.stdout else 0}")
            logger.debug(f"目标 {target} stderr长度: {len(result.stderr) if result.stderr else 0}")
            
            if result.returncode != 0:
                logger.error(f"miniscan-port执行失败，目标: {target}, 返回码: {result.returncode}")
                logger.error(f"错误输出: {result.stderr}")
                return None
            
            # 检查JSON结果文件是否存在
            json_result_file = temp_result_file
            # 等待文件生成，最多 3 秒
            if not os.path.exists(json_result_file):
                import time
                for _ in range(30):
                    if os.path.exists(json_result_file):
                        break
                    time.sleep(0.1)
            # 兼容老逻辑：如果仍不存在，尝试 temp_result_file + '.json'
            if not os.path.exists(json_result_file) and os.path.exists(temp_result_file + '.json'):
                logger.warning(f"目标 {target} JSON结果文件未找到，使用兼容路径: {temp_result_file + '.json'}")
                json_result_file = temp_result_file + '.json'
            if not os.path.exists(json_result_file):
                logger.warning(f"目标 {target} JSON结果文件不存在: {json_result_file}")
                return None
            
            logger.debug(f"目标 {target} 开始解析JSON文件: {json_result_file}")
            
            # 从JSON文件读取结果
            parsed_results = self._parse_json_file(json_result_file)
            
            if parsed_results:
                logger.debug(f"目标 {target} 解析成功，获得 {len(parsed_results)} 个结果")
                # 返回第一个结果（单个目标扫描通常只有一个结果）
                return parsed_results[0] if parsed_results else None
            else:
                logger.warning(f"目标 {target} 解析失败")
                return None
            
        except subprocess.TimeoutExpired:
            logger.error(f"扫描目标 {target} 超时")
            return None
        except Exception as e:
            logger.error(f"执行miniscan-port时发生错误，目标: {target}, 错误: {str(e)}")
            import traceback
            logger.debug(f"详细错误信息: {traceback.format_exc()}")
            return None
        finally:
            # 清理临时文件
            if temp_result_file and os.path.exists(temp_result_file):
                try:
                    os.unlink(temp_result_file)
                    logger.debug(f"临时结果文件已清理: {temp_result_file}")
                except Exception as e:
                    logger.warning(f"清理临时结果文件失败: {e}")
    
    def _parse_json_file(self, json_file_path):
        """
        从JSON文件解析miniscan-port的扫描结果
        
        Args:
            json_file_path (str): JSON结果文件路径
            
        Returns:
            list: 解析后的结果列表
        """
        logger.debug(f"开始解析JSON文件: {json_file_path}")
        
        try:
            # 检查文件是否存在
            if not os.path.exists(json_file_path):
                logger.error(f"JSON文件不存在: {json_file_path}")
                return []
            
            # 读取JSON文件
            with open(json_file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            logger.debug(f"JSON文件大小: {len(content)} 字符")
            
            if not content:
                logger.warning("JSON文件为空")
                return []
            
            # 解析JSON
            data = json.loads(content)
            logger.debug(f"JSON解析成功，数据类型: {type(data)}")
            
            # 检查数据结构
            if isinstance(data, dict):
                logger.debug(f"JSON为字典，键: {list(data.keys())}")
                # 处理单个扫描结果
                return self._parse_single_json_result(data)
            elif isinstance(data, list):
                logger.debug(f"JSON为列表，长度: {len(data)}")
                # 处理多个扫描结果
                results = []
                for item in data:
                    parsed = self._parse_single_json_result(item)
                    if parsed:
                        results.extend(parsed)
                return results
            else:
                logger.warning(f"未识别的JSON数据类型: {type(data)}")
                return []
                
        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {str(e)}")
            logger.debug(f"文件内容前500字符: {content[:500] if 'content' in locals() else 'N/A'}")
            return []
        except Exception as e:
            logger.error(f"解析JSON文件时发生错误: {str(e)}")
            import traceback
            logger.debug(f"详细错误信息: {traceback.format_exc()}")
            return []
    
    def _parse_single_json_result(self, data):
        """
        解析单个JSON扫描结果
        
        Args:
            data (dict): 单个扫描结果数据
            
        Returns:
            list: 解析后的结果列表
        """
        logger.debug(f"解析单个JSON结果，数据键: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
        
        if not isinstance(data, dict):
            logger.warning(f"数据不是字典类型: {type(data)}")
            return []
        
        # 检查是否有open_ports字段
        if 'open_ports' not in data:
            logger.warning("JSON数据中没有找到open_ports字段")
            return []
        
        open_ports = data.get('open_ports', [])
        logger.debug(f"发现 {len(open_ports)} 个开放端口")
        
        if not open_ports:
            logger.debug("没有开放端口")
            return []
        
        # 按主机分组端口信息
        host_ports = {}
        for port_data in open_ports:
            host = port_data.get('host', '')
            if not host:
                logger.warning(f"端口数据缺少host字段: {port_data}")
                continue
            
            if host not in host_ports:
                host_ports[host] = []
            
            # 构建端口信息
            port_info = {
                'port_id': port_data.get('port', 0),
                'service_name': port_data.get('service', ''),
                'version': '',  # miniscan-port通常不提供版本信息
                'product': port_data.get('service', ''),
                'protocol': 'tcp'  # 默认为tcp
            }
            
            host_ports[host].append(port_info)
        
        # 构建最终结果
        results = []
        for host, ports in host_ports.items():
            logger.debug(f"主机 {host} 有 {len(ports)} 个开放端口")
            
            result = {
                'ip': host,
                'port_info': ports,
                'os_info': {}
            }
            results.append(result)
        
        logger.debug(f"解析完成，返回 {len(results)} 个主机结果")
        return results
        """
        从miniscan-port的输出中提取JSON部分
        miniscan-port的输出包含ASCII艺术字和进度信息，需要提取纯JSON部分
        
        Args:
            output: miniscan-port的完整输出
            
        Returns:
            str: 提取的JSON字符串，如果没有找到则返回None
        """
        logger.debug(f"开始提取JSON，输出总长度: {len(output)}")
        logger.debug(f"输出前200字符: {output[:200]}")
        
        try:
            # 查找JSON开始位置（第一个 '{' 字符）
            json_start = output.find('{')
            if json_start == -1:
                logger.warning("未找到JSON开始字符'{'")
                return None
            
            # 查找JSON结束位置（最后一个 '}' 字符）
            json_end = output.rfind('}')
            if json_end == -1 or json_end <= json_start:
                logger.warning(f"未找到有效的JSON结束字符'}}', json_start: {json_start}, json_end: {json_end}")
                return None
            
            logger.debug(f"JSON边界位置 - 开始: {json_start}, 结束: {json_end}")
            
            # 提取JSON部分
            json_str = output[json_start:json_end + 1].strip()
            
            logger.debug(f"提取的JSON长度: {len(json_str)}")
            logger.debug(f"提取的JSON前200字符: {json_str[:200]}")
            
            # 验证提取的内容是否为有效JSON
            json.loads(json_str)
            logger.debug("JSON验证成功")
            return json_str
            
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"提取JSON时发生错误: {e}")
            logger.debug(f"错误的JSON内容: {json_str[:500] if 'json_str' in locals() else 'N/A'}")
            return None
    
    def _parse_miniscan_output(self, output, target):
        """解析miniscan-port的输出"""
        logger.debug(f"开始解析目标 {target} 的输出")
        
        try:
            if not output.strip():
                logger.warning(f"目标 {target} 输出为空")
                return None
            
            # 提取JSON部分 - miniscan-port输出包含非JSON内容
            json_str = self._extract_json_from_output(output)
            if not json_str:
                logger.warning(f"无法从输出中提取JSON内容，目标: {target}")
                return None
            
            # 尝试解析JSON
            data = json.loads(json_str)
            logger.debug(f"目标 {target} JSON解析成功，数据类型: {type(data)}")
            
            # 检查数据结构
            if isinstance(data, dict):
                logger.debug(f"目标 {target} JSON为字典，键: {list(data.keys())}")
            elif isinstance(data, list):
                logger.debug(f"目标 {target} JSON为列表，长度: {len(data)}")
            
            # 提取端口信息 - 适配新的输出格式
            port_info = []
            
            # 新格式：直接使用 open_ports 字段
            if 'open_ports' in data and data['open_ports']:
                logger.debug(f"目标 {target} 使用新格式（open_ports），端口数量: {len(data['open_ports'])}")
                for port_data in data['open_ports']:
                    port_info.append({
                        'port_id': port_data.get('port', 0),
                        'service_name': port_data.get('service', ''),
                        'version': port_data.get('version', ''),
                        'title': port_data.get('title', ''),
                        'banner': port_data.get('banner', ''),
                        'host': port_data.get('host', target)  # 新增host字段
                    })
            
            # 兼容旧格式：results.ports 结构
            elif 'results' in data and data['results']:
                logger.debug(f"目标 {target} 使用旧格式（results.ports）")
                for result in data['results']:
                    if 'ports' in result and result['ports']:
                        logger.debug(f"目标 {target} 发现端口数量: {len(result['ports'])}")
                        for port_data in result['ports']:
                            port_info.append({
                                'port_id': port_data.get('port', 0),
                                'service_name': port_data.get('service', ''),
                                'version': port_data.get('version', ''),
                                'title': port_data.get('title', ''),
                                'banner': port_data.get('banner', '')
                            })
            else:
                logger.warning(f"目标 {target} 未识别的JSON格式: {json_str[:200]}")
            
            logger.debug(f"目标 {target} 最终解析出 {len(port_info)} 个端口")
            
            return {
                'ip': target,
                'port_info': port_info
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"解析miniscan-port JSON输出失败: {str(e)}")
            logger.debug(f"原始输出内容: {output[:500]}...")  # 只记录前500字符
            return None
        except Exception as e:
            logger.error(f"处理miniscan-port输出时发生错误: {str(e)}")
            import traceback
            logger.debug(f"详细错误信息: {traceback.format_exc()}")
            return None

    def _parse_batch_output(self, output):
        """
        解析批量扫描的输出
        
        Args:
            output: miniscan-port的输出
            
        Returns:
            list: ARL格式的扫描结果列表
        """
        logger.info(f"开始解析批量扫描输出，输出长度: {len(output)} 字符")
        
        ip_info_list = []
        
        try:
            # 提取JSON部分 - miniscan-port输出包含非JSON内容
            json_str = self._extract_json_from_output(output)
            if not json_str:
                logger.warning("无法从批量扫描输出中提取JSON内容，尝试解析控制台输出")
                return self._parse_console_batch_output(output)
            
            logger.info("检测到JSON格式输出，开始解析")
            data = json.loads(json_str)
            
            # 处理单个结果对象
            if isinstance(data, dict):
                logger.info("解析单个JSON对象")
                result = self._parse_single_result(data)
                if result:
                    ip_info_list.append(result)
            
            # 处理结果数组
            elif isinstance(data, list):
                logger.info(f"解析JSON数组，包含 {len(data)} 个元素")
                for item in data:
                    result = self._parse_single_result(item)
                    if result:
                        ip_info_list.append(result)
        
        except json.JSONDecodeError as e:
            logger.error(f"解析批量扫描JSON输出失败: {e}，尝试解析控制台输出")
            ip_info_list = self._parse_console_batch_output(output)
        except Exception as e:
            logger.error(f"解析批量扫描输出时发生异常: {e}")
            ip_info_list = []
        
        logger.info(f"批量扫描完成，发现 {len(ip_info_list)} 个有结果的目标")
        return ip_info_list
    
    def _parse_single_result(self, data):
        """
        解析单个扫描结果
        
        Args:
            data: 单个结果的数据
            
        Returns:
            dict: ARL格式的扫描结果
        """
        # 新格式检查：直接包含 open_ports 字段
        if 'open_ports' in data:
            # 从target字段获取目标，如果是文件名则需要特殊处理
            target = data.get('target', 'unknown')
            if target.endswith('.txt'):
                # 如果target是文件名，需要从open_ports中的host字段获取实际IP
                if data['open_ports']:
                    target = data['open_ports'][0].get('host', target)
            
            port_info_list = []
            
            for port_data in data['open_ports']:
                port_info = {
                    "port_id": port_data.get('port', 0),
                    "service_name": port_data.get('service', ''),
                    "version": port_data.get('version', ''),  # 新格式可能包含版本信息
                    "product": port_data.get('product', ''),  # 新格式可能包含产品信息
                    "protocol": 'tcp',  # 默认TCP协议
                    "host": port_data.get('host', target)  # 保存实际主机信息
                }
                port_info_list.append(port_info)
            
            if not port_info_list:
                return None
            
            # 构建IP信息
            ip_info = {
                "ip": target,
                "port_info": port_info_list,
                "os_info": {}
            }
            
            return ip_info
        
        # 兼容旧格式：检查 target 字段
        elif 'target' in data:
            target = data['target']
            port_info_list = []
            
            # 解析开放端口
            if 'open_ports' in data:
                for port_data in data['open_ports']:
                    port_info = {
                        "port_id": port_data.get('port', 0),
                        "service_name": port_data.get('service', ''),
                        "version": '',  # miniscan-port可能不提供版本信息
                        "product": '',  # miniscan-port可能不提供产品信息
                        "protocol": 'tcp'  # 默认TCP协议
                    }
                    port_info_list.append(port_info)
            
            if not port_info_list:
                return None
            
            # 构建IP信息
            ip_info = {
                "ip": target,
                "port_info": port_info_list,
                "os_info": {}
            }
            
            return ip_info
        
        # 如果都不匹配，返回None
        return None
    
    def _parse_console_batch_output(self, output):
        """
        解析批量扫描的控制台输出
        
        Args:
            output: 控制台输出文本
            
        Returns:
            list: ARL格式的扫描结果列表
        """
        ip_info_dict = {}  # 使用字典按IP分组
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # 查找开放端口信息，格式如: "192.168.1.100:80 [HTTP]"
            if ':' in line and '[' in line and ']' in line:
                try:
                    # 提取IP和端口
                    ip_port = line.split('[')[0].strip()
                    if ':' in ip_port:
                        ip, port = ip_port.split(':')
                        
                        # 提取服务名
                        service_start = line.find('[')
                        service_end = line.find(']')
                        service_name = ''
                        if service_start != -1 and service_end != -1:
                            service_name = line[service_start+1:service_end]
                        
                        port_info = {
                            "port_id": int(port),
                            "service_name": service_name.lower(),
                            "version": '',
                            "product": '',
                            "protocol": 'tcp'
                        }
                        
                        # 按IP分组
                        if ip not in ip_info_dict:
                            ip_info_dict[ip] = {
                                "ip": ip,
                                "port_info": [],
                                "os_info": {}
                            }
                        
                        ip_info_dict[ip]["port_info"].append(port_info)
                        
                except (ValueError, IndexError) as e:
                    logger.debug(f"解析端口信息失败: {line}, 错误: {str(e)}")
                    continue
        
        # 转换为列表
        return list(ip_info_dict.values())
    
    def _parse_console_output(self, output, target):
        """
        解析miniscan-port的控制台输出
        
        Args:
            output: 控制台输出文本
            target: 目标IP
            
        Returns:
            dict: ARL格式的扫描结果
        """
        port_info_list = []
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # 查找开放端口信息，格式如: "192.168.1.100:80 [HTTP]"
            if ':' in line and '[' in line and ']' in line:
                try:
                    # 提取IP和端口
                    ip_port = line.split('[')[0].strip()
                    if ':' in ip_port:
                        ip, port = ip_port.split(':')
                        
                        # 提取服务名
                        service_start = line.find('[')
                        service_end = line.find(']')
                        service_name = ''
                        if service_start != -1 and service_end != -1:
                            service_name = line[service_start+1:service_end]
                        
                        port_info = {
                            "port_id": int(port),
                            "service_name": service_name.lower(),
                            "version": '',
                            "product": '',
                            "protocol": 'tcp'
                        }
                        port_info_list.append(port_info)
                        
                except (ValueError, IndexError) as e:
                    continue
        
        # 构建IP信息
        ip_info = {
            "ip": target,
            "port_info": port_info_list,
            "os_info": {}
        }
        
        return ip_info if port_info_list else None


def port_scan(targets, ports=Config.TOP_10, service_detect=False, os_detect=False,
              port_parallelism=32, port_min_rate=64, custom_host_timeout=None, port_scan_type=None):
    """
    使用miniscan-port进行端口扫描的函数
    保持与原有nmap接口的兼容性
    
    Args:
        targets: 目标IP列表
        ports: 端口范围
        service_detect: 服务检测（miniscan-port暂不支持）
        os_detect: OS检测（miniscan-port暂不支持）
        port_parallelism: 并发数
        port_min_rate: 最小速率（miniscan-port中对应线程数）
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
    scanner = MiniscanPortScan(
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