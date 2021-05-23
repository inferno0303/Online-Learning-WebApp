# author: wjl
# version: 20190511
# student service

import flask
import pymysql
import redis
import configparser
import datetime
import hashlib
import time
import json
from orm import db, user, question_answer, chapter_1, student_info, admin

app = flask.Flask(__name__)

db_config = configparser.ConfigParser()
db_config.read('database_config.ini')
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql://' + db_config.get('DB', 'DB_USER') + ':' + db_config.get('DB', 'DB_PASSWORD') + '@' + db_config.get('DB', 'DB_HOST') + '/' + db_config.get('DB', 'DB_DB')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config["SQLALCHEMY_ECHO"] = False
db.init_app(app)

pymysql.install_as_MySQLdb()

pool = redis.ConnectionPool(host='imyx.top', password='Teemo1234', port=6379, db=0, socket_connect_timeout=1, decode_responses=True)
rs = redis.Redis(connection_pool=pool)


# TODO 修改请求头允许跨域请求 param: data return: response obj 已弃用 2019年5月10日 19:07:28
def response(data):
    data = flask.make_response(data)
    data.headers['Access-Control-Allow-Origin'] = '*'
    return data


# TODO test
@app.route('/hello')
def _hello_world():
    return flask.make_response('<h1>hello world python flask</h1>')


# TODO index
@app.route('/')
def _index():
    return flask.make_response(flask.render_template('entry/index.html'))


"""
学生用户逻辑开始
"""


# TODO 注册学生账户
@app.route('/api/register/', methods=['POST'])
def register():
    try:
        params = flask.request.form.to_dict()
        print(params)
        username = params['username']
        password = params['password']
        email = params['email']
        phone_number = params['phone_number']
        if username is not None and password is not None and email is not None and phone_number is not None:
            new_rec = user(username=username, password=password, email=email, phone_number=phone_number, admin_flag='no')
            db.session.add(new_rec)
            new_rec_2 = student_info(student_id=username)
            db.session.add(new_rec_2)
            db.session.commit()
            return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': '注册成功'}}))
        else:
            return flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '注册失败'}}))
    except Exception as e:
        print(e)
        return flask.make_response(flask.jsonify({'data': {'code': '-2', 'msg': '其他错误'}}))


# TODO 检测cookie有效性
@app.route('/api/check_cookie/', methods=['GET'])
def check_cookie():
    try:
        old_cookie = flask.request.cookies.get('LOGIN_SESSION')
        if old_cookie is None:
            print('新cookie-set')
            md5 = hashlib.md5()
            md5.update(str(time.time()).encode())
            new_cookie = str(md5.hexdigest())
            # TODO 写redis，set-cookie到前端
            rs.set(name=new_cookie, value='', ex=5000)
            resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': 'New cookie set: ' + new_cookie}}))
            resp.set_cookie('LOGIN_SESSION', value=new_cookie,
                            expires=datetime.datetime.now() + datetime.timedelta(hours=240))
            return resp
        elif old_cookie is not None:
            v = rs.get(name=old_cookie)
            if v == '':
                # TODO 有cookie但未登录
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '登录状态无效，请输入用户名密码'}}))
                return resp
            elif v is None:
                # TODO redis无值，写值进redis
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '登录状态无效，请输入用户名密码'}}))
                return resp
            else:
                # TODO cookie有效
                rs.set(name=old_cookie, value=v, ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': '自动登陆成功，跳转到首页'}}))
                return resp
    except Exception as e:
        print(e)
        flask.abort(500)


# TODO 登陆逻辑，POST接收提交表单密码，GET接收ajax自动登陆请求
@app.route('/api/login/', methods=['POST', 'GET'])
def api_login():
    try:
        if flask.request.method == 'POST':
            # TODO login页面的登陆POST
            params = flask.request.form
            params = params.to_dict()
            username = params['username']
            password = params['password']
            old_cookie = flask.request.cookies.get('LOGIN_SESSION')
            db_resp = user.query.filter(user.username == username, user.password == password).first()
            if db_resp and old_cookie is not None:
                # TODO 如果用户名密码正确
                rs.set(name=old_cookie, value=username, ex=5000)
                resp = flask.make_response(flask.render_template('redirect_page/login_success.html', username=username))
                return resp
            elif db_resp is None and old_cookie is not None:
                # TODO 如果用户名密码不正确
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.render_template('redirect_page/login_faild.html'))
                return resp
            else:
                # TODO 没cookie，登陆个屁，回login
                resp = flask.make_response(flask.render_template('redirect_page/login_faild.html'))
                return resp
        elif flask.request.method == 'GET':
            permission_check_result = permission_check(flask.request.cookies.get('LOGIN_SESSION'))
            if permission_check_result == 'OK':
                # TODO 使用cookie自动登陆
                username = rs.get(flask.request.cookies.get('LOGIN_SESSION'))
                resp = flask.make_response(
                    flask.render_template('redirect_page/login_sucess_by_cookie.html', username=username))
                return resp
            else:
                return permission_check_result
    except Exception as e:
        print(e)
        return flask.abort(403)


# TODO 用户名密码错误
@app.route('/login_err/')
def login_err():
    resp = flask.render_template('redirect_page/login_faild.html')
    return resp


# TODO 退出登陆页面，先验证cookie有效性，再清空cookie
@app.route('/api/exit_login/', methods=['GET'])
def exit_login():
    try:
        permission_check_result = permission_check(flask.request.cookies.get('LOGIN_SESSION'))
        if permission_check_result == 'OK':
            # TODO 删除cookie，删除redis的cookie，前端回到首页
            rs.delete(flask.request.cookies.get('LOGIN_SESSION'))
            resp = flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': '退出登录成功'}}))
            resp.delete_cookie('LOGIN_SESSION')
            return resp
        else:
            return permission_check_result
    except Exception as e:
        print(e)
        return flask.abort(403)


# TODO 每次访问需要权限的资源时，验证cookie是否有效，return OK则有效，否则return resp包含错误码，前端会自动路由
def permission_check(old_cookie):
    try:
        if old_cookie is None:
            # TODO 如果没有cookie，回到login
            resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '无资源访问权限，cookie为空'}}))
            return resp
        elif old_cookie is not None:
            # TODO 如果有cookie，判断cookie是否有效
            v = rs.get(name=old_cookie)
            if v == '':
                # TODO cookie未登录
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '登录状态无效，请输入用户名密码'}}))
                return resp
            elif v is None:
                # TODO redis无值，写值进redis
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '登录状态无效，请输入用户名密码'}}))
                return resp
            else:
                # TODO cookie有效
                rs.set(name=old_cookie, value=v, ex=5000)
                return 'OK'
    except Exception as e:
        print(e)
        return False


# TODO 获取题目，GET argv: c // chapter章节，1~6
@app.route('/api/get_topic/', methods=['GET'])
def get_topic():
    permission_check_result = permission_check(flask.request.cookies.get('LOGIN_SESSION'))
    if permission_check_result == 'OK':
        # TODO 权限有效，进入正常后端逻辑
        c = flask.request.args.get("c")
        all_t = chapter_1.query.filter(chapter_1.chapter == c).all()
        ret = []
        for each_t in all_t:
            ret.append({'topic_id': each_t.topic_id, 'topic': each_t.topic, 'option_A': each_t.option_A,
                        'option_B': each_t.option_B, 'option_C': each_t.option_C, 'option_D': each_t.option_D,
                        'correct_answer': each_t.correct_answer, 'explain': each_t.explain})
        return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': ret}}))
    else:
        return permission_check_result


# TODO 提交答案，评分，记录到数据库，POST params: c // chapter章节，1~6
@app.route('/api/submit_answer/', methods=['POST'])
def submit_answer():
    permission_check_result = permission_check(flask.request.cookies.get('LOGIN_SESSION'))
    if permission_check_result == 'OK':
        # TODO 权限有效，进入正常后端逻辑
        params = flask.request.form.to_dict()
        c = params['c']
        options = params['options']
        options = json.loads(options)
        # TODO 查库，打分
        total_score = 0
        wrong_topic_id = []
        for each_option in options:
            topic_id = each_option['topic_id']
            option = each_option['option']
            correct_answer = chapter_1.query.filter(chapter_1.chapter == c, chapter_1.topic_id == topic_id).value(
                chapter_1.correct_answer)
            if option == correct_answer:
                total_score += 10
            else:
                wrong_topic_id.append(topic_id)
        # TODO 将错题和分数写入数据库
        student_id = rs.get(flask.request.cookies.get('LOGIN_SESSION'))
        db_rec = student_info.query.filter(student_info.student_id == student_id).first()
        if db_rec:
            if c == '1':
                db_rec.chapter_1_score = total_score
                db_rec.chapter_1_wrong_topic_id = str(wrong_topic_id)
            elif c == '2':
                db_rec.chapter_2_score = total_score
                db_rec.chapter_2_wrong_topic_id = str(wrong_topic_id)
            elif c == '3':
                db_rec.chapter_3_score = total_score
                db_rec.chapter_3_wrong_topic_id = str(wrong_topic_id)
            elif c == '4':
                db_rec.chapter_4_score = total_score
                db_rec.chapter_4_wrong_topic_id = str(wrong_topic_id)
            elif c == '5':
                db_rec.chapter_5_score = total_score
                db_rec.chapter_5_wrong_topic_id = str(wrong_topic_id)
            elif c == '6':
                db_rec.chapter_6_score = total_score
                db_rec.chapter_6_wrong_topic_id = str(wrong_topic_id)
            db.session.commit()
        print(total_score, wrong_topic_id)
        return flask.make_response(
            flask.jsonify({'data': {'code': '0', 'msg': {'score': total_score, 'wrong_topic_id': wrong_topic_id}}}))
    else:
        return permission_check_result


# TODO 获取学生成绩，GET argv: c // chapter章节，1~6
@app.route('/api/get_student_score/', methods=['GET'])
def get_student_score():
    permission_check_result = permission_check(flask.request.cookies.get('LOGIN_SESSION'))
    c = flask.request.args.get("c")
    if permission_check_result == 'OK':
        # TODO 权限有效，进入正常后端逻辑
        username = rs.get(flask.request.cookies.get('LOGIN_SESSION'))
        score = None
        wrong_topic_id = None
        if c == '1':
            score = student_info.query.filter(student_info.student_id == username).value(student_info.chapter_1_score)
            wrong_topic_id = student_info.query.filter(student_info.student_id == username).value(
                student_info.chapter_1_wrong_topic_id)
        elif c == '2':
            score = student_info.query.filter(student_info.student_id == username).value(student_info.chapter_2_score)
            wrong_topic_id = student_info.query.filter(student_info.student_id == username).value(
                student_info.chapter_2_wrong_topic_id)
        elif c == '3':
            score = student_info.query.filter(student_info.student_id == username).value(student_info.chapter_3_score)
            wrong_topic_id = student_info.query.filter(student_info.student_id == username).value(
                student_info.chapter_3_wrong_topic_id)
        elif c == '4':
            score = student_info.query.filter(student_info.student_id == username).value(student_info.chapter_4_score)
            wrong_topic_id = student_info.query.filter(student_info.student_id == username).value(
                student_info.chapter_4_wrong_topic_id)
        elif c == '5':
            score = student_info.query.filter(student_info.student_id == username).value(student_info.chapter_5_score)
            wrong_topic_id = student_info.query.filter(student_info.student_id == username).value(
                student_info.chapter_5_wrong_topic_id)
        elif c == '6':
            score = student_info.query.filter(student_info.student_id == username).value(student_info.chapter_6_score)
            wrong_topic_id = student_info.query.filter(student_info.student_id == username).value(
                student_info.chapter_6_wrong_topic_id)
        else:
            return flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': 'params error'}}))
        return flask.make_response(flask.jsonify(
            {'data': {'code': '0', 'msg': {"student_id": username, "score": score, "wrong_topic_id": wrong_topic_id}}}))
    else:
        return permission_check_result


# TODO 获取所有评论
@app.route('/api/get_comment/', methods=['GET'])
def get_comment():
    permission_check_result = permission_check(flask.request.cookies.get('LOGIN_SESSION'))
    if permission_check_result == 'OK':
        # TODO 权限有效，进入正常后端逻辑
        all_q = question_answer.query.all()
        ret = []
        for each_q in all_q:
            ret.append({'question': each_q.question, 'student_id': each_q.student_id, 'answer': each_q.answer,
                        'question_time': str(each_q.question_time), 'answer_time': str(each_q.answer_time)})
        return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': ret}}))
    else:
        return permission_check_result


# TODO 提交评论，以cookie的用户名为准
@app.route('/api/submit_comment/', methods=['POST'])
def submit_comment():
    permission_check_result = permission_check(flask.request.cookies.get('LOGIN_SESSION'))
    if permission_check_result == 'OK':
        # TODO 权限有效，进入正常后端逻辑
        params = flask.request.form
        params = params.to_dict()
        comment_text = params['comment_text']
        print(comment_text)
        # TODO 将评论内容写进数据库
        new_q = question_answer(question=comment_text,
                                student_id=rs.get(flask.request.cookies.get('LOGIN_SESSION')),
                                question_time=datetime.datetime.now())
        db.session.add(new_q)
        db.session.commit()
        resp = flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': '留言成功'}}))
        return resp
    else:
        return permission_check_result


"""
TODO 管理员逻辑开始
"""


# TODO 返回admin登陆页
@app.route('/admin/login/', methods=['GET'])
def _admin_page_login():
    return flask.render_template('administrator/admin_login.html')


# TODO admin登录页 检测cookie有效性
@app.route('/admin/api/check_cookie/', methods=['GET'])
def _admin_check_cookie():
    try:
        old_cookie = flask.request.cookies.get('ADMIN_SESSION')
        if old_cookie is None:
            md5 = hashlib.md5()
            md5.update(str(time.time()).encode())
            new_cookie = str(md5.hexdigest())
            # TODO 写redis，set-cookie到前端
            rs.set(name=new_cookie, value='', ex=5000)
            resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': 'New cookie set: ' + new_cookie}}))
            resp.set_cookie('ADMIN_SESSION', value=new_cookie, expires=datetime.datetime.now() + datetime.timedelta(hours=240))
            return resp
        elif old_cookie is not None:
            v = rs.get(name=old_cookie)
            if v == '':
                # TODO 有cookie但未登录
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '登录状态无效，请输入用户名密码'}}))
                return resp
            elif v is None:
                # TODO redis该cookie值，刷新页面
                md5 = hashlib.md5()
                md5.update(str(time.time()).encode())
                new_cookie = str(md5.hexdigest())
                rs.set(name=new_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': 'New cookie set: ' + new_cookie}}))
                resp.set_cookie('ADMIN_SESSION', value=new_cookie,expires=datetime.datetime.now() + datetime.timedelta(hours=240))
                return resp
            else:
                # TODO cookie有效
                rs.set(name=old_cookie, value=v, ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': '自动登陆成功，跳转到首页'}}))
                return resp
    except Exception as e:
        print(e)
        flask.abort(500)


# TODO admin登陆逻辑，POST接收提交表单密码
@app.route('/admin/api/login/', methods=['POST'])
def _admin_api_login():
    try:
        if flask.request.method == 'POST':
            # TODO login页面的登陆POST
            params = flask.request.form
            params = params.to_dict()
            username = params['username']
            password = params['password']
            old_cookie = flask.request.cookies.get('ADMIN_SESSION')
            db_resp = admin.query.filter(admin.username == username, admin.password == password).first()
            if db_resp and old_cookie is not None:
                # TODO 如果用户名密码正确
                rs.set(name=old_cookie, value=username, ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': '登陆成功'}}))
                return resp
            elif db_resp is None and old_cookie is not None:
                # TODO 如果用户名密码不正确
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '登陆失败'}}))
                return resp
            else:
                # TODO 没cookie，登陆个屁，回login
                resp = flask.make_response(flask.jsonify({'data': {'code': '-2', 'msg': '没cookie，刷新首页'}}))
                return resp
        elif flask.request.method == 'GET':
            return flask.abort(403)
    except Exception as e:
        print(e)
        return flask.abort(403)


# TODO 返回admin退出登陆页
@app.route('/admin/exit_login/', methods=['GET'])
def _admin_exit_login():
    return flask.render_template('administrator/exit_login.html')


# TODO 管理员退出登陆api
@app.route('/admin/api/exit_login/', methods=['GET'])
def _admin_api_exit_login():
    try:
        permission_check_result = permission_check(flask.request.cookies.get('ADMIN_SESSION'))
        if permission_check_result == 'OK':
            # TODO 删除cookie，删除redis的cookie，前端回到首页
            rs.delete(flask.request.cookies.get('ADMIN_SESSION'))
            resp = flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': '退出登录成功'}}))
            resp.delete_cookie('ADMIN_SESSION')
            return resp
        else:
            return permission_check_result
    except Exception as e:
        print(e)
        return flask.abort(403)


# TODO 每次访问需要权限的资源时，验证cookie是否有效，return OK则有效，否则return resp包含错误码，前端会自动路由
def _admin_permission_check(old_cookie):
    try:
        if old_cookie is None:
            # TODO 如果没有cookie，回到login
            resp = flask.make_response(flask.jsonify({'data': {'code': '-2', 'msg': '无资源访问权限，cookie为空'}}))
            return resp
        elif old_cookie is not None:
            # TODO 如果有cookie，判断cookie是否有效
            v = rs.get(name=old_cookie)
            if v == 'admin':
                rs.set(name=old_cookie, value=v, ex=5000)
                return 'OK'
            if v == '':
                # TODO cookie未登录，回登录页
                rs.set(name=old_cookie, value='', ex=5000)
                resp = flask.make_response(flask.jsonify({'data': {'code': '-2', 'msg': '登录状态无效，请输入用户名密码'}}))
                return resp
            elif v is None:
                # TODO redis无值，回登录页
                resp = flask.make_response(flask.jsonify({'data': {'code': '-2', 'msg': '登录状态无效，请输入用户名密码'}}))
                return resp
    except Exception as e:
        print(e)
        return flask.make_response(flask.jsonify({'data': {'code': '-2', 'msg': 'err status'}}))


# TODO 返回后台留言管理页
@app.route('/admin/qa_manager/', methods=['GET'])
def _admin_qa_manager():
    return flask.render_template('administrator/qa_manager.html')


# TODO 后台留言管理页api，获取所有留言
@app.route('/admin/api/get_all_qa/', methods=['GET'])
def _admin_api_get_all_qa():
    permission_check_result = _admin_permission_check(flask.request.cookies.get('ADMIN_SESSION'))
    if permission_check_result == 'OK':
        # TODO 进入正常后端逻辑
        all_q = question_answer.query.all()
        ret = []
        for each_q in all_q:
            ret.append({'id': each_q.id, 'question': each_q.question, 'student_id': each_q.student_id, 'answer': each_q.answer,
                        'question_time': str(each_q.question_time), 'answer_time': str(each_q.answer_time)})
        return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': ret}}))
    else:
        return permission_check_result


# TODO 删除留言api
@app.route('/admin/api/delete_qa/', methods=['POST'])
def _admin_api_delete_qa():
    permission_check_result = _admin_permission_check(flask.request.cookies.get('ADMIN_SESSION'))
    if permission_check_result == 'OK':
        params = flask.request.form.to_dict()
        qa_id = params['qa_id']
        print(qa_id)
        if qa_id is not None:
            db_rec = question_answer.query.filter(question_answer.id == qa_id).first()
            try:
                db.session.delete(db_rec)
                db.session.commit()
                return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': qa_id}}))
            except Exception as e:
                print(e)
                return flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '删除失败'}}))
    else:
        return permission_check_result


# TODO 更新留言api
@app.route('/admin/api/update_qa/', methods=['POST'])
def _admin_api_update_qa():
    permission_check_result = _admin_permission_check(flask.request.cookies.get('ADMIN_SESSION'))
    if permission_check_result == 'OK':
        params = flask.request.form.to_dict()
        qa_id = params['qa_id']
        new_answer = params['new_answer']
        print(qa_id, new_answer)
        if qa_id is not None:
            db_rec = question_answer.query.filter(question_answer.id == qa_id).first()
            try:
                db_rec.answer = new_answer
                db_rec.answer_time = datetime.datetime.now()
                db.session.commit()
                return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': new_answer}}))
            except Exception as e:
                print(e)
                return flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '删除失败'}}))
    else:
        return permission_check_result


# TODO 返回后台练习题管理页
@app.route('/admin/topic_manager/', methods=['GET'])
def _admin_topic_manager():
    return flask.render_template('administrator/topic_manager.html')


# TODO 管理员获取题目，GET argv: c // chapter章节，1~6
@app.route('/admin/api/get_topic/', methods=['GET'])
def _admin_get_topic():
    permission_check_result = permission_check(flask.request.cookies.get('ADMIN_SESSION'))
    if permission_check_result == 'OK':
        # TODO 权限有效，进入正常后端逻辑
        c = flask.request.args.get("c")
        all_t = chapter_1.query.filter(chapter_1.chapter == c).all()
        ret = []
        for each_t in all_t:
            ret.append({'id': each_t.id, 'topic_id': each_t.topic_id, 'topic': each_t.topic, 'option_A': each_t.option_A,
                        'option_B': each_t.option_B, 'option_C': each_t.option_C, 'option_D': each_t.option_D,
                        'correct_answer': each_t.correct_answer, 'explain': each_t.explain})
        return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': ret}}))
    else:
        return permission_check_result


# TODO 更新题目api
@app.route('/admin/api/update_topic/', methods=['POST'])
def _admin_api_update_topic():
    permission_check_result = _admin_permission_check(flask.request.cookies.get('ADMIN_SESSION'))
    if permission_check_result == 'OK':
        params = flask.request.form.to_dict()
        topic_id = params['topic_id']
        tm_value = params['tm_value']
        ao_value = params['ao_value']
        bo_value = params['bo_value']
        co_value = params['co_value']
        do_value = params['do_value']
        an_value = params['an_value']
        js_value = params['js_value']
        print(topic_id, tm_value, ao_value, bo_value, co_value, do_value, an_value, js_value)
        if topic_id is not None and tm_value is not None and tm_value is not None and ao_value is not None and bo_value is not None and co_value is not None and do_value is not None and an_value is not None and js_value is not None:
            db_rec = chapter_1.query.filter(chapter_1.id == topic_id).first()
            try:
                print(db_rec)
                db_rec.topic = tm_value
                db_rec.option_A = ao_value
                db_rec.option_B = bo_value
                db_rec.option_C = co_value
                db_rec.option_D = do_value
                db_rec.correct_answer = an_value
                db_rec.explain = js_value
                db.session.commit()
                return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': topic_id}}))
            except Exception as e:
                print(e)
                return flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '删除失败'}}))
    else:
        return permission_check_result


# TODO 删除题目api
@app.route('/admin/api/delete_topic/', methods=['POST'])
def _admin_api_delete_topic():
    try:
        permission_check_result = _admin_permission_check(flask.request.cookies.get('ADMIN_SESSION'))
        if permission_check_result == 'OK':
            params = flask.request.form.to_dict()
            topic_id = params['topic_id']
            if topic_id is not None:
                db_rec = chapter_1.query.filter(chapter_1.id == topic_id).first()
                if db_rec is not None:
                    try:
                        db.session.delete(db_rec)
                        db.session.commit()
                        return flask.make_response(flask.jsonify({'data': {'code': '0', 'msg': topic_id}}))
                    except Exception as e:
                        print(e)
                        return flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '删除失败'}}))
        else:
            return permission_check_result
    except Exception as e:
        print(e)
        return flask.make_response(flask.jsonify({'data': {'code': '-1', 'msg': '内部错误'}}))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=82, debug=False, threaded=True)
