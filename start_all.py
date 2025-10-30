#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARL 一键启动脚本
用于独立部署模式下一键启动所有服务（Web、Worker、Scheduler）
"""

import os
import sys
import argparse
import yaml
import subprocess
import time
import signal
from pathlib import Path

# 添加app目录到Python路径
current_dir = Path(__file__).parent
app_dir = current_dir / "app"
sys.path.insert(0, str(app_dir))


def load_config(config_file):
    """
    加载配置文件
    
    Args:
        config_file (str): 配置文件路径
        
    Returns:
        dict: 配置字典
    """
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"加载配置文件失败: {e}")
        sys.exit(1)


def check_dependencies(config):
    """
    检查外部依赖连接
    
    Args:
        config (dict): 配置字典
    """
    print("正在检查外部依赖连接...")
    
    # 检查MongoDB连接
    try:
        from pymongo import MongoClient
        mongo_uri = config.get('MONGO', {}).get('URI', 'mongodb://localhost:27017/')
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        client.server_info()
        print("✓ MongoDB连接正常")
    except Exception as e:
        print(f"✗ MongoDB连接失败: {e}")
        print("请确保MongoDB服务已启动并且连接配置正确")
        return False
    
    # 检查RabbitMQ连接
    try:
        import pika
        broker_url = config.get('CELERY', {}).get('BROKER_URL', '')
        if broker_url.startswith('amqp://'):
            # 解析RabbitMQ连接参数
            from urllib.parse import urlparse
            parsed = urlparse(broker_url)
            credentials = pika.PlainCredentials(parsed.username, parsed.password)
            parameters = pika.ConnectionParameters(
                host=parsed.hostname,
                port=parsed.port or 5672,
                virtual_host=parsed.path[1:] if parsed.path else '/',
                credentials=credentials
            )
            connection = pika.BlockingConnection(parameters)
            connection.close()
            print("✓ RabbitMQ连接正常")
    except Exception as e:
        print(f"✗ RabbitMQ连接失败: {e}")
        print("请确保RabbitMQ服务已启动并且连接配置正确")
        return False
    
    return True


def start_service(script_name, service_name, config_file, extra_args=None):
    """
    启动服务
    
    Args:
        script_name (str): 启动脚本名称
        service_name (str): 服务名称
        config_file (str): 配置文件路径
        extra_args (list): 额外参数
        
    Returns:
        subprocess.Popen: 进程对象
    """
    cmd = [sys.executable, script_name, '--config', config_file, '--skip-check']
    if extra_args:
        cmd.extend(extra_args)
    
    print(f"启动 {service_name}...")
    return subprocess.Popen(cmd)


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description='ARL 一键启动脚本')
    parser.add_argument(
        '--config', 
        default='app/config-standalone.yaml',
        help='配置文件路径 (默认: app/config-standalone.yaml)'
    )
    parser.add_argument(
        '--services',
        nargs='+',
        choices=['web', 'worker', 'scheduler'],
        default=['web', 'worker', 'scheduler'],
        help='指定要启动的服务 (默认: 全部)'
    )
    parser.add_argument(
        '--skip-check',
        action='store_true',
        help='跳过依赖检查'
    )
    parser.add_argument(
        '--web-port',
        type=int,
        default=None,
        help='Web服务端口'
    )
    parser.add_argument(
        '--web-host',
        default=None,
        help='Web服务主机'
    )
    parser.add_argument(
        '--worker-concurrency',
        type=int,
        default=None,
        help='Worker并发数'
    )
    
    args = parser.parse_args()
    
    # 检查配置文件是否存在
    if not os.path.exists(args.config):
        print(f"配置文件不存在: {args.config}")
        print("请先复制 app/config-standalone.yaml 并根据实际环境修改配置")
        sys.exit(1)
    
    # 加载配置
    config = load_config(args.config)
    
    # 检查依赖连接
    if not args.skip_check:
        if not check_dependencies(config):
            print("\n依赖检查失败，请检查外部服务状态")
            print("如果要跳过检查强制启动，请使用 --skip-check 参数")
            sys.exit(1)
    
    print(f"\n正在启动ARL服务...")
    print(f"配置文件: {args.config}")
    print(f"启动服务: {', '.join(args.services)}")
    
    processes = []
    
    try:
        # 启动Worker (如果需要)
        if 'worker' in args.services:
            worker_args = []
            if args.worker_concurrency:
                worker_args.extend(['--concurrency', str(args.worker_concurrency)])
            
            process = start_service('start_worker.py', 'Worker', args.config, worker_args)
            processes.append(('Worker', process))
            time.sleep(2)  # 等待Worker启动
        
        # 启动Scheduler (如果需要)
        if 'scheduler' in args.services:
            process = start_service('start_scheduler.py', 'Scheduler', args.config)
            processes.append(('Scheduler', process))
            time.sleep(2)  # 等待Scheduler启动
        
        # 启动Web服务 (如果需要)
        if 'web' in args.services:
            web_args = []
            if args.web_host:
                web_args.extend(['--host', args.web_host])
            if args.web_port:
                web_args.extend(['--port', str(args.web_port)])
            
            process = start_service('start_web.py', 'Web服务', args.config, web_args)
            processes.append(('Web服务', process))
        
        print(f"\n所有服务已启动，共 {len(processes)} 个进程")
        print("服务状态:")
        for name, process in processes:
            status = "运行中" if process.poll() is None else "已停止"
            print(f"  {name}: {status}")
        
        print("\n按 Ctrl+C 停止所有服务")
        
        # 等待所有进程
        while True:
            time.sleep(1)
            # 检查进程状态
            for name, process in processes:
                if process.poll() is not None:
                    print(f"\n警告: {name} 进程已退出 (退出码: {process.returncode})")
            
    except KeyboardInterrupt:
        print("\n正在停止所有服务...")
        for name, process in processes:
            try:
                print(f"停止 {name}...")
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print(f"强制终止 {name}...")
                process.kill()
        print("所有服务已停止")
    except Exception as e:
        print(f"启动失败: {e}")
        # 清理已启动的进程
        for name, process in processes:
            try:
                process.terminate()
            except:
                pass
        sys.exit(1)


if __name__ == '__main__':
    main()