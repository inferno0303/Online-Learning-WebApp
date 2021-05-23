from flask_sqlalchemy import SQLAlchemy

# MySQL映射
db = SQLAlchemy()


# TODO 学生ORM
class user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.VARCHAR)
    password = db.Column(db.VARCHAR)
    email = db.Column(db.VARCHAR)
    phone_number = db.Column(db.VARCHAR)
    admin_flag = db.Column(db.VARCHAR)

    def __repr__(self):
        return '<ORM repr> (%s, %s, %s, %s)' % (self.id, self.username, self.password, self.admin_flag)


class question_answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.VARCHAR)
    student_id = db.Column(db.VARCHAR)
    answer = db.Column(db.VARCHAR)
    question_time = db.Column(db.DateTime)
    answer_time = db.Column(db.DateTime)
    flag = db.Column(db.VARCHAR)

    def __repr__(self):
        return '<ORM repr> (%s, %s, %s, %s)' % (self.id, self.question, self.answer, self.question_time)


class chapter_1(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chapter = db.Column(db.VARCHAR)
    topic_id = db.Column(db.VARCHAR)
    topic = db.Column(db.VARCHAR)
    option_A = db.Column(db.VARCHAR)
    option_B = db.Column(db.VARCHAR)
    option_C = db.Column(db.VARCHAR)
    option_D = db.Column(db.VARCHAR)
    correct_answer = db.Column(db.VARCHAR)
    explain = db.Column(db.VARCHAR)

    def __repr__(self):
        return '<ORM repr> (%s, %s, %s, %s)' % (self.id, self.chapter, self.topic_id, self.topic)


class student_info(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.VARCHAR)
    student_name = db.Column(db.VARCHAR)
    last_login = db.Column(db.DateTime)
    chapter_1_score = db.Column(db.VARCHAR)
    chapter_1_wrong_topic_id = db.Column(db.VARCHAR)
    chapter_2_score = db.Column(db.VARCHAR)
    chapter_2_wrong_topic_id = db.Column(db.VARCHAR)
    chapter_3_score = db.Column(db.VARCHAR)
    chapter_3_wrong_topic_id = db.Column(db.VARCHAR)
    chapter_4_score = db.Column(db.VARCHAR)
    chapter_4_wrong_topic_id = db.Column(db.VARCHAR)
    chapter_5_score = db.Column(db.VARCHAR)
    chapter_5_wrong_topic_id = db.Column(db.VARCHAR)
    chapter_6_score = db.Column(db.VARCHAR)
    chapter_6_wrong_topic_id = db.Column(db.VARCHAR)
    flag = db.Column(db.VARCHAR)

    def __repr__(self):
        return '<ORM repr> (%s, %s, %s, %s)' % (self.id, self.student_id, self.chapter_1_score, self.chapter_2_score)


# TODO 管理员ORM
class admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.VARCHAR)
    password = db.Column(db.VARCHAR)
    email = db.Column(db.VARCHAR)
    phone_number = db.Column(db.VARCHAR)
    admin_flag = db.Column(db.VARCHAR)

    def __repr__(self):
        return '<ORM repr> (%s, %s, %s, %s)' % (self.id, self.username, self.password, self.admin_flag)