# -*- coding: utf-8 -*-
import json

import arrow

from app import db, app
from app.models import *
from app.helper import *


def test_scope_get():
    scope = Scope.query.all()
    for i in scope:
        print i.name

def test_user_get():
    user = Users.query.filter_by(username='admin', banned=0).first()
    print user.scope
    
def test_traffic_get():
    r = Traffic.query.first()
    #help(r)
    print type(r.pass_time)
    #print r.crossing_id

def test_vehicle_add():
    t = arrow.now().format('YYYY-MM-DD HH:mm:ss')
    v = Vehicle(date_created=t, date_modify=t, hphm=u'粤L12345',hpzl='01',
                info=u'"fuck":123')
    db.session.add(v)
    db.session.commit()

def test_vehicle_get():
    v = Vehicle.query.filter_by(hphm=u'粤L12345',hpzl='01').first()
    print json.loads(v.info)

def test_vehicle_set():
    v = Vehicle.query.filter_by(hphm=u'粤L12345',hpzl='01').first()
    v.hpzl = '12'
    db.session.commit()


if __name__ == '__main__':
    #test_vehicle_add()
    #test_vehicle_get()
    test_vehicle_set()


