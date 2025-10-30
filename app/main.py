import os
from flask import Flask, send_from_directory, send_file
from flask_restx import Api

from app import routes
from app.utils import arl_update

# 获取项目根目录和前端文件目录
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
frontend_dir = os.path.join(basedir, 'docker', 'frontend')

# 配置Flask应用，指定静态文件目录
arl_app = Flask(__name__, static_folder=frontend_dir, static_url_path='')
arl_app.config['BUNDLE_ERRORS'] = True

authorizations = {
    "ApiKeyAuth": {
        "type": "apiKey",
        "in": "header",
        "name": "Token"
    }
}

api = Api(arl_app, prefix="/api", doc="/api/doc", title='ARL backend API', authorizations=authorizations,
          description='ARL（Asset Reconnaissance Lighthouse）资产侦察灯塔系统', security="ApiKeyAuth", version="2.6")

api.add_namespace(routes.task_ns)
api.add_namespace(routes.site_ns)
api.add_namespace(routes.domain_ns)
api.add_namespace(routes.ip_ns)
api.add_namespace(routes.url_ns)
api.add_namespace(routes.user_ns)
api.add_namespace(routes.image_ns)
api.add_namespace(routes.cert_ns)
api.add_namespace(routes.service_ns)
api.add_namespace(routes.fileleak_ns)
api.add_namespace(routes.export_ns)
api.add_namespace(routes.asset_scope_ns)
api.add_namespace(routes.asset_domain_ns)
api.add_namespace(routes.asset_ip_ns)
api.add_namespace(routes.asset_site_ns)
api.add_namespace(routes.scheduler_ns)
api.add_namespace(routes.poc_ns)
api.add_namespace(routes.vuln_ns)
api.add_namespace(routes.batch_export_ns)
api.add_namespace(routes.policy_ns)
api.add_namespace(routes.npoc_service_ns)
api.add_namespace(routes.task_fofa_ns)
api.add_namespace(routes.console_ns)
api.add_namespace(routes.cip_ns)
api.add_namespace(routes.fingerprint_ns)
api.add_namespace(routes.stat_finger_ns)
api.add_namespace(routes.github_task_ns)
api.add_namespace(routes.github_result_ns)
api.add_namespace(routes.github_scheduler_ns)
api.add_namespace(routes.github_monitor_result_ns)
api.add_namespace(routes.task_schedule_ns)
api.add_namespace(routes.nuclei_result_ns)
api.add_namespace(routes.wih_ns)
api.add_namespace(routes.asset_wih_ns)


# 添加前端路由处理
@arl_app.route('/')
def index():
    """
    返回前端主页
    """
    return send_file(os.path.join(frontend_dir, 'index.html'))

# 添加错误处理器来处理404错误
@arl_app.errorhandler(404)
def handle_404(e):
    """
    处理404错误，对于非API请求返回前端页面
    """
    # 获取请求路径
    path = e.description if hasattr(e, 'description') else str(e)
    
    # 如果是API请求，返回JSON格式的404错误
    if hasattr(e, 'original_exception') and hasattr(e.original_exception, 'endpoint'):
        if str(e.original_exception.endpoint).startswith('api'):
            return {"message": "API endpoint not found"}, 404
    
    # 检查请求路径
    from flask import request
    request_path = request.path
    
    # 如果是API请求，返回JSON格式的404错误
    if request_path.startswith('/api/'):
        return {"message": "API endpoint not found"}, 404
    
    # 检查是否是静态文件请求
    if '.' in request_path.split('/')[-1]:
        # 尝试从frontend目录提供静态文件
        try:
            return send_from_directory(frontend_dir, request_path.lstrip('/'))
        except:
            return "File not found", 404
    
    # 对于其他所有请求（前端路由），返回index.html让Vue Router处理
    return send_file(os.path.join(frontend_dir, 'index.html'))


arl_update()

if __name__ == '__main__':
    arl_app.run(debug=True, port=5018, host="0.0.0.0")
