# -*- coding: utf-8 -*-
import suds
from suds.client import Client
from xml.etree import ElementTree


def handle_hphm(hphm):
    if hphm[-1] in set([u'学', u'警']):
	return hphm[1:-1]
    return hphm[1:]


def get_vehicle(hphm, hpzl):
    url = u'http://127.0.0.1:8989/EhlService.asmx?wsdl'
    client = Client(url)
    hp = handle_hphm(hphm)
    sf = hphm[0]
    if sf is None or sf == u'粤':
        jkid = '01C21'
        doc = u"<?xml version='1.0' encoding='GBK'?><root><QueryCondition><hpzl>{1}</hpzl><hphm>{0}</hphm></QueryCondition></root>".format(hp, hpzl)
    else:
        jkid = '01C49'
        doc = u"<?xml version='1.0' encoding='GBK'?><root><QueryCondition><sf>{2}</sf><hpzl>{1}</hpzl><hphm>{0}</hphm></QueryCondition></root>".format(hp, hpzl, sf)
    s = client.service.queryObjectOut(jkid=jkid, QueryXmlDoc=doc)
    root = ElementTree.fromstring(s.encode('utf8').replace('GBK', 'utf-8'))
    try:
	result = {}
	for i in root.getchildren()[1].getchildren()[0]:
	    result[i.tag] = i.text
        return result
    except Exception as e:
        return None


if __name__ == "__main__":
    hpzl = '16'
    #hphm = u'粤L30999'
    #hphm = u'AED257'
    hphm = u'粤L0821学'
    print get_vehicle(hphm, hpzl)
