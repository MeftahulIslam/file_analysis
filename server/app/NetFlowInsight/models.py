from . import db
from flask_login import UserMixin
from sqlalchemy import func
import pytz,datetime

def get_current_time():
    return datetime.datetime.now(pytz.timezone('Europe/Vilnius'))



#Tables on the database
class PcapLoc(db.Model):
    __tablename__ = 'pcaploc'
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(1000))
    filename = db.Column(db.String(1000))
    date = db.Column(db.DateTime(timezone=True), default=get_current_time)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_analysis = db.relationship('FileAnalysis', backref='pcap_loc', lazy=True)
    note = db.relationship('Notes')



class FileAnalysis(db.Model):
    __tablename__ = 'fileanalysis'
    id = db.Column(db.Integer, primary_key=True)
    pcap_loc_id = db.Column(db.Integer, db.ForeignKey('pcaploc.id'))
    path = db.Column(db.String(1000))
    date = db.Column(db.DateTime(timezone=True), default=get_current_time)
    file_result = db.relationship('FileResult')

class FileResult(db.Model):
    __tablename__='fileresult'
    id = db.Column(db.Integer, primary_key=True)
    mime_type = db.Column(db.String(20))
    filename = db.Column(db.String(100))
    extension_type=db.Column(db.String(100))
    result = db.Column(db.String(1000000000000000))
    filepath = db.Column(db.String(1000))
    file_analysis_id = db.Column(db.Integer, db.ForeignKey('fileanalysis.id'))

class Notes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=get_current_time)
    pcap_loc_id = db.Column(db.Integer, db.ForeignKey('pcaploc.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    firstname = db.Column(db.String(150))
    lastname = db.Column(db.String(150))
    path = db.Column(db.String(150))
    api_key = db.Column(db.String(100), nullable=True, default="default_api_key")
    pcap_loc = db.relationship('PcapLoc')