import json
import os
import subprocess

from app.config import Config
from app import utils


logger = utils.get_logger()


class NucleiScan(object):
    def __init__(self, targets: list):
        self.targets = targets

        tmp_path = Config.TMP_PATH
        rand_str = utils.random_choices()

        self.nuclei_target_path = os.path.join(tmp_path,
                                               "nuclei_target_{}.txt".format(rand_str))

        self.nuclei_result_path = os.path.join(tmp_path,
                                               "nuclei_result_{}.json".format(rand_str))

        self.vscan_result_path = os.path.join(tmp_path,
                                               "vscan_result_{}.json".format(rand_str))

        self.nuclei_bin_path = "nuclei"

        self.vscan_bin_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools", "vscanPlus")

        # 在nuclei 2.9.1 中 将-json 参数改成了 -jsonl 参数。
        self.nuclei_json_flag = None

    def _delete_file(self):
        """
        删除临时文件
        """
        files_to_delete = [self.nuclei_target_path, self.nuclei_result_path, self.vscan_result_path]
        
        for file_path in files_to_delete:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    logger.info(f"已删除临时文件: {file_path}")
                except Exception as e:
                    logger.warning(f"删除临时文件失败 {file_path}: {e}")
            else:
                logger.debug(f"临时文件不存在，无需删除: {file_path}")

    def _gen_target_file(self):
        """
        生成目标文件
        """
        with open(self.nuclei_target_path, "w") as f:
            for domain in self.targets:
                domain = domain.strip()
                if not domain:
                    continue
                f.write(domain + "\n")

    def dump_result(self, result_file=None):
        """
        解析 vscanPlus 扫描结果文件
        支持真实的 vscanPlus 输出格式：单行 JSON 对象
        
        Args:
            result_file: 结果文件路径，如果为None则使用默认路径
        """
        if result_file is None:
            result_file = self.vscan_result_path
            
        if not os.path.exists(result_file):
            logger.warning(f"结果文件不存在: {result_file}")
            return []
        
        if os.path.getsize(result_file) == 0:
            logger.warning(f"结果文件为空: {result_file}")
            return []
        
        results = []
        
        try:
            with open(result_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
            if not content:
                logger.warning(f"结果文件内容为空: {result_file}")
                return []
            
            # 记录原始输出用于调试
            logger.info(f"vscanPlus 原始输出: {content[:200]}...")
            
            # 尝试解析为单个 JSON 对象（真实的 vscanPlus 输出格式）
            try:
                data = json.loads(content)
                logger.info("成功解析 vscanPlus JSON 输出")
                parsed_results = self._parse_real_vscanplus_result(data)
                results.extend(parsed_results)
                        
            except json.JSONDecodeError as e:
                logger.error(f"解析 vscanPlus JSON 输出失败: {e}")
                # 尝试逐行解析作为备用方案
                logger.info("尝试逐行解析作为备用方案")
                for line in content.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        parsed_results = self._parse_real_vscanplus_result(data)
                        results.extend(parsed_results)
                    except json.JSONDecodeError as line_e:
                        logger.warning(f"解析 JSON 行失败: {line[:100]}..., 错误: {line_e}")
                        continue
                        
        except Exception as e:
            logger.error(f"读取结果文件失败: {result_file}, 错误: {e}")
            return []
        
        logger.info(f"成功解析 {len(results)} 个扫描结果")
        return results
    
    def _parse_real_vscanplus_result(self, data):
        """
        解析真实的vscanPlus扫描结果
        真实格式包含字段：url, technologies, POC, title, host 等
        """
        results = []
        
        try:
            # 提取基本信息
            target = data.get('url', data.get('input', ''))
            if not target:
                logger.warning("扫描结果中缺少目标URL")
                return results
            
            title = data.get('title', '')
            host = data.get('host', '')
            
            # 提取技术栈信息
            technologies = data.get('technologies', [])
            if not isinstance(technologies, list):
                technologies = []
            
            # 提取POC信息
            poc_list = data.get('POC', [])
            if not isinstance(poc_list, list):
                poc_list = []
            
            logger.info("目标: {}, 技术栈: {}, POC: {}".format(target, technologies, poc_list))
            
            # 处理技术栈检测结果
            if technologies:
                tech_result = {
                    "template_url": target,
                    "template_id": "tech_detection",
                    "vuln_name": "技术栈检测: {}".format(', '.join(technologies)),
                    "vuln_severity": "info",
                    "vuln_url": target,
                    "curl_command": "curl -X GET '{}'".format(target),
                    "target": target
                }
                if title:
                    tech_result["vuln_name"] += " (标题: {})".format(title)
                results.append(tech_result)
            
            # 处理POC检测结果
            if poc_list:
                for poc in poc_list:
                    poc_result = {
                        "template_url": target,
                        "template_id": "poc_detection",
                        "vuln_name": "POC检测: {}".format(poc),
                        "vuln_severity": "medium",
                        "vuln_url": target,
                        "curl_command": "curl -X GET '{}'".format(target),
                        "target": target
                    }
                    results.append(poc_result)
            
            # 如果既没有技术栈也没有POC，创建一个基础记录
            if not technologies and not poc_list:
                basic_result = {
                    "template_url": target,
                    "template_id": "basic_scan",
                    "vuln_name": "基础扫描完成",
                    "vuln_severity": "info",
                    "vuln_url": target,
                    "curl_command": "curl -X GET '{}'".format(target),
                    "target": target
                }
                if title:
                    basic_result["vuln_name"] += " (标题: {})".format(title)
                results.append(basic_result)
            
        except Exception as e:
            logger.error("解析vscanPlus结果失败: {}".format(str(e)))
        
        return results

    def exec_nuclei(self):
        """
        执行vscanPlus扫描
        """
        # 生成目标文件
        self._gen_target_file()
        
        # 检查目标文件是否生成成功
        if not os.path.exists(self.nuclei_target_path):
            logger.error(f"目标文件生成失败: {self.nuclei_target_path}")
            return
            
        # 检查目标文件内容
        try:
            with open(self.nuclei_target_path, 'r', encoding='utf-8') as f:
                target_content = f.read().strip()
            if not target_content:
                logger.warning(f"目标文件为空: {self.nuclei_target_path}")
                return
            logger.info(f"目标文件内容: {target_content}")
        except Exception as e:
            logger.error(f"读取目标文件失败: {e}")
            return

        logger.info("开始执行vscanPlus扫描")

        # 检查vscanPlus文件类型并选择合适的执行方式
        import stat
        import platform
        
        # 检查文件是否存在
        if not os.path.exists(self.vscan_bin_path):
            raise FileNotFoundError(f"vscanPlus工具不存在: {self.vscan_bin_path}")
        
        # 读取文件头部判断文件类型
        try:
            with open(self.vscan_bin_path, 'rb') as f:
                header = f.read(4)
            
            # 检查是否为二进制可执行文件
            is_binary = False
            if platform.system() == "Linux":
                # Linux ELF文件头
                is_binary = header.startswith(b'\x7fELF')
            elif platform.system() == "Windows":
                # Windows PE文件头
                is_binary = header.startswith(b'MZ')
            
            # 如果不是二进制文件，检查是否为脚本文件
            if not is_binary:
                with open(self.vscan_bin_path, 'r', encoding='utf-8') as f:
                    first_line = f.readline().strip()
                    is_script = first_line.startswith('#!')
            else:
                is_script = False
                
        except Exception as e:
            logger.warning(f"无法读取vscanPlus文件头: {e}")
            is_binary = False
            is_script = False
        
        # 根据文件类型和权限选择执行方式
        if is_binary and os.access(self.vscan_bin_path, os.X_OK):
            # 直接执行二进制文件
            command = [
                self.vscan_bin_path,
                "-l", self.nuclei_target_path,
                "-json",
                "-o", self.vscan_result_path
            ]
        elif is_script:
            # 执行脚本文件
            if platform.system() == "Windows":
                # Windows下，如果没有bash，则使用python执行
                try:
                    import subprocess
                    subprocess.run(['bash', '--version'], capture_output=True, check=True)
                    # bash可用，使用bash执行
                    command = [
                        "bash",
                        self.vscan_bin_path,
                        "-l", self.nuclei_target_path,
                        "-json",
                        "-o", self.vscan_result_path
                    ]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # bash不可用，使用python执行
                    command = [
                        "python",
                        self.vscan_bin_path,
                        "-l", self.nuclei_target_path,
                        "-json",
                        "-o", self.vscan_result_path
                    ]
            else:
                # Linux下直接执行脚本
                command = [
                    self.vscan_bin_path,
                    "-l", self.nuclei_target_path,
                    "-json",
                    "-o", self.vscan_result_path
                ]
        else:
            # 尝试用python执行
            python_cmd = "python3" if platform.system() != "Windows" else "python"
            command = [
                python_cmd,
                self.vscan_bin_path,
                "-l", self.nuclei_target_path,
                "-json",
                "-o", self.vscan_result_path
            ]

        logger.info("vscanPlus命令: {}".format(" ".join(command)))

        try:
            # 执行命令
            result = utils.exec_system(command, timeout=96*60*60)
            logger.info(f"vscanPlus执行完成，返回码: {result}")
            
            # 检查结果文件是否生成
            if os.path.exists(self.vscan_result_path):
                file_size = os.path.getsize(self.vscan_result_path)
                logger.info(f"结果文件已生成: {self.vscan_result_path}, 大小: {file_size} 字节")
                
                # 如果文件不为空，记录前几行内容用于调试
                if file_size > 0:
                    try:
                        with open(self.vscan_result_path, 'r', encoding='utf-8') as f:
                            preview = f.read(500)
                        logger.info(f"结果文件预览: {preview}")
                    except Exception as e:
                        logger.warning(f"读取结果文件预览失败: {e}")
                else:
                    logger.warning(f"结果文件为空: {self.vscan_result_path}")
            else:
                logger.error(f"结果文件未生成: {self.vscan_result_path}")
                
        except Exception as e:
            logger.error(f"执行vscanPlus失败: {e}")
            raise

    def run(self):
        """
        执行nuclei扫描的主方法
        """
        logger.info(f"开始nuclei扫描，目标数量: {len(self.targets)}")
        
        try:
            # 执行vscanPlus扫描
            self.exec_nuclei()
            
            # 解析扫描结果
            results = self.dump_result()
            logger.info(f"nuclei扫描完成，获得结果数量: {len(results)}")
            
            return results
            
        except Exception as e:
            logger.error(f"nuclei扫描过程中发生错误: {e}")
            return []
            
        finally:
            # 确保临时文件被清理
            try:
                self._delete_file()
            except Exception as e:
                logger.warning(f"清理临时文件时发生错误: {e}")


def nuclei_scan(targets: list):
    """
    执行nuclei扫描（实际使用vscanPlus工具）
    
    Args:
        targets: 目标列表
        
    Returns:
        list: 扫描结果列表
    """
    if not targets:
        return []

    n = NucleiScan(targets=targets)
    return n.run()

