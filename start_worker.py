#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARL Worker服务独立启动脚本
用于独立部署模式下启动Celery Worker
"""

import os
import sys
import argparse
import yaml
import subprocess
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


def start_worker(queue_name, worker_name, concurrency, log_file):
    """
    启动单个Worker进程
    
    Args:
        queue_name (str): 队列名称
        worker_name (str): Worker名称
        concurrency (int): 并发数
        log_file (str): 日志文件路径
    """
    cmd = [
        sys.executable, '-m', 'celery',
        '-A', 'app.celerytask.celery',
        'worker',
        '-l', 'info',
        '-Q', queue_name,
        '-n', worker_name,
        '-c', str(concurrency),
        '-O', 'fair',
        '-f', log_file
    ]
    
    print(f"启动Worker: {worker_name} (队列: {queue_name}, 并发: {concurrency})")
    return subprocess.Popen(cmd)


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description='ARL Worker服务独立启动脚本')
    parser.add_argument(
        '--config', 
        default='app/config-standalone.yaml',
        help='配置文件路径 (默认: app/config-standalone.yaml)'
    )
    parser.add_argument(
        '--queue',
        choices=['arltask', 'arlgithub', 'all'],
        default='all',
        help='指定要启动的队列 (默认: all)'
    )
    parser.add_argument(
        '--concurrency',
        type=int,
        default=None,
        help='Worker并发数'
    )
    parser.add_argument(
        '--log-file',
        default='arl_worker.log',
        help='日志文件路径 (默认: arl_worker.log)'
    )
    parser.add_argument(
        '--skip-check',
        action='store_true',
        help='跳过依赖检查'
    )
    
    args = parser.parse_args()
    
    # 检查配置文件是否存在
    if not os.path.exists(args.config):
        print(f"配置文件不存在: {args.config}")
        print("请先复制 app/config-standalone.yaml 并根据实际环境修改配置")
        sys.exit(1)
    
    # 加载配置
    config = load_config(args.config)
    
    # 设置配置文件环境变量，让app/config.py能够找到配置文件
    os.environ['ARL_CONFIG_FILE'] = os.path.abspath(args.config)
    
    # 检查依赖连接
    if not args.skip_check:
        if not check_dependencies(config):
            print("\n依赖检查失败，请检查外部服务状态")
            print("如果要跳过检查强制启动，请使用 --skip-check 参数")
            sys.exit(1)
    
    # 获取Worker配置
    worker_config = config.get('WORKER', {})
    concurrency = args.concurrency or worker_config.get('CONCURRENCY', 2)
    queues = worker_config.get('QUEUES', ['arltask', 'arlgithub'])
    
    print(f"\n正在启动ARL Worker服务...")
    print(f"配置文件: {args.config}")
    print(f"日志文件: {args.log_file}")
    
    processes = []
    
    try:
        if args.queue == 'all':
            # 启动所有队列的Worker
            for queue in queues:
                worker_name = queue
                process = start_worker(queue, worker_name, concurrency, args.log_file)
                processes.append(process)
        else:
            # 启动指定队列的Worker
            worker_name = args.queue
            process = start_worker(args.queue, worker_name, concurrency, args.log_file)
            processes.append(process)
        
        print(f"\n所有Worker已启动，共 {len(processes)} 个进程")
        print("按 Ctrl+C 停止所有Worker")
        
        # 等待所有进程
        for process in processes:
            process.wait()
            
    except KeyboardInterrupt:
        print("\n正在停止所有Worker...")
        for process in processes:
            try:
                process.terminate()
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        print("所有Worker已停止")
    except Exception as e:
        print(f"启动失败: {e}")
        # 清理已启动的进程
        for process in processes:
            try:
                process.terminate()
            except:
                pass
        sys.exit(1)


if __name__ == '__main__':
    main()