#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARL Web服务独立启动脚本
用于独立部署模式下启动Web服务
"""

import os
import sys
import argparse
import yaml
from pathlib import Path

# 添加app目录到Python路径
current_dir = Path(__file__).parent
app_dir = current_dir / "app"
sys.path.insert(0, str(app_dir))

from app.main import arl_app
from app.utils import arl_update


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


def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(description='ARL Web服务独立启动脚本')
    parser.add_argument(
        '--config', 
        default='app/config-standalone.yaml',
        help='配置文件路径 (默认: app/config-standalone.yaml)'
    )
    parser.add_argument(
        '--host',
        default=None,
        help='监听主机地址'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=None,
        help='监听端口'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='启用调试模式'
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
    
    # 获取Web服务配置
    web_config = config.get('WEB', {})
    host = args.host or web_config.get('HOST', '0.0.0.0')
    port = args.port or web_config.get('PORT', 5003)
    debug = args.debug or web_config.get('DEBUG', False)
    
    print(f"\n正在启动ARL Web服务...")
    print(f"监听地址: {host}:{port}")
    print(f"调试模式: {debug}")
    print(f"配置文件: {args.config}")
    
    # 执行更新检查
    try:
        arl_update()
    except Exception as e:
        print(f"更新检查失败: {e}")
    
    # 启动Flask应用
    try:
        if debug:
            arl_app.run(debug=True, host=host, port=port)
        else:
            # 生产模式使用gunicorn
            try:
                import gunicorn.app.wsgiapp as wsgi
                sys.argv = [
                    'gunicorn',
                    '--bind', f'{host}:{port}',
                    '--workers', '3',
                    '--access-logfile', 'arl_web.log',
                    '--access-logformat', '%({x-real-ip}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"',
                    'app.main:arl_app'
                ]
                wsgi.run()
            except ImportError:
                print("gunicorn未安装，使用Flask开发服务器")
                arl_app.run(debug=False, host=host, port=port)
    except KeyboardInterrupt:
        print("\n服务已停止")
    except Exception as e:
        print(f"启动失败: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()