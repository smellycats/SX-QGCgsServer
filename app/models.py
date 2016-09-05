# -*- coding: utf-8 -*-
import arrow

from . import db


class Users(db.Model):
    """用户"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), index=True)
    password = db.Column(db.String(128))
    scope = db.Column(db.String(128), default='')
    date_created = db.Column(db.DateTime, default=arrow.now().datetime)
    date_modified = db.Column(db.DateTime, default=arrow.now().datetime)
    banned = db.Column(db.Integer, default=0)

    def __init__(self, username, password, scope='', banned=0,
                 date_created=None, date_modified=None):
        self.username = username
        self.password = password
        self.scope = scope
        now = arrow.now().datetime
        if not date_created:
            self.date_created = now
        if not date_modified:
            self.date_modified = now
        self.banned = banned

    def __repr__(self):
        return '<Users %r>' % self.id


class Scope(db.Model):
    """权限范围"""
    __tablename__ = 'scope'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Scope %r>' % self.id


class Vehicle(db.Model):
    """用户cltx表id关联"""
    __tablename__ = 'vehicle'
    __bind_key__ = 'cgs'
    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime)
    date_modify = db.Column(db.DateTime)
    hphm = db.Column(db.String(16))
    hpzl = db.Column(db.String(2))
    info = db.Column(db.String(1024))

    def __init__(self, date_created, date_modify, hphm, hpzl, info):
        self.date_created = date_created
        self.date_modify = date_modify
	self.hphm = hphm
	self.hpzl = hpzl
	self.info = info


    def __repr__(self):
        return '<Vehicle %r>' % self.id

