#!/usr/bin/env python
import sys
import yaml
import datetime
import logging
import os
from logging.handlers import RotatingFileHandler
from time import sleep
from rq_scheduler import Scheduler
from redis import Redis, StrictRedis
from rq import get_failed_queue,Queue
from rq.job import Job
from pprint import pprint 
import argparse

from threat_feeds.threat_intelligence_base import Threat_intelligence_base
from utils.manage_elasticsearch import Manage_elasticsearch
from utils.geoip_mapping import Geoip_mapping

# threat intelligence feed classes
from threat_feeds.zeus_tracker import Zeus_tracker
from threat_feeds.Feodo_tracker import Feodo_tracker
from threat_feeds.malwaredomains import Malwaredomains
from threat_feeds.abuse_ssh_blacklist import Abuse_ssh_blacklist
from threat_feeds.yoyo_adwarelist import Yoyo_adware

# set up rotating file handler
#logging.basicConfig(level=logging.INFO)
#log = logging.getLogger('threat-feeds-logger')
#handler = logging.handlers.RotatingFileHandler('threat-feeds.log',maxbytes=100000,backupCount=5)
#formatter = logging.Formatter('%(asctime)s- %(name)s - %(levelname)s - %(message)s')
#handler.setFormatter(formatter)
#log.addHandler(handler)

# setup logging
logging.basicConfig(stream = sys.stdout, level = logging.ERROR)
log = logging.getLogger('threat-feeds-logger')

def get_configuration(configuration_file):
    threat_feeds_settings = redis_settings = proxy_settings = None
    try:
        config_file = os.path.join(os.path.dirname(__file__), configuration_file)
        log.info("Reading configuration file - %s" % config_file)
        with open(config_file, 'r') as f:
            config_data = yaml.load(f)
            threat_feed_settings, redis_settings, proxy_settings = config_data['feeds'], config_data['redis'],config_data['proxy']
            log.debug("Threat-feeds settings - %s" % threat_feed_settings)
            log.debug("Redis settings - %s" % redis_settings)
            log.debug("Proxy settings - %s" % proxy_settings)
            log.info("Configuration file - '%s' is read successfully." % config_file)
    except Exception, exc:
        log.error("Error while reading configuration file %s:\n %s" %(config_file, exc.message), exc_info = True)
    
    return threat_feed_settings, redis_settings, proxy_settings

def setup_redis(queue_name='default', host_name = '127.0.0.1', port_no = 6379):
    redis_scheduler = None
    try:
        log.info("Setting up Redis connection")
        redis_con = StrictRedis(host = host_name, port = port_no)
        redis_scheduler = Scheduler(queue_name, connection = redis_con)	
        log.info("Redis connection is now setup successfully.")
    except Exception, exc:
        log.error("Error while setting up Redis connection to %s:%s\n %s" %(host,port,exc.message), exc_info = True)
    return redis_scheduler

def check_elasticsearch(feed_settings):

    try:
        status_check = False 
        for out_mode in feed_settings['output']:
            if 'elastic' in out_mode['type'].lower():
                el_host = out_mode['host'] 
                el_port = out_mode['port']
                el_index = out_mode['index']    
                el_doctype = out_mode['doc_type']
                el_enabled = out_mode['enabled']

                log.debug("""Elastic host:{}, Elastic port:{}, Elastic index:{},Elastic document type:{} Enabled: {}"""
                        .format(el_host,el_port,el_index,el_doctype, el_enabled))

                # create elasticsearch instance
                el_instance = Manage_elasticsearch(el_host,el_port,el_index,el_doctype)
                es_health = el_instance.check_health()
                if not es_health:
                    log.info("""Failed to connect to Elasticsearch server.Kindly re-check Elasticsearch settings and then try again""")
                return status_check

                # check if elasticsearch index exists. If not, create a new elastic index.
                index_present = el_instance.index_exists(el_index)
                if not index_present: 
                    response = el_instance.create_index(el_index) 
                status_check = True
    except Exception, exc:
        log.error("Error while setting up elasticsearch connection - %s" % exc.message, exc_info=True)

    return status_check

def download_feeds(feed_settings, proxy_settings, redis_connection=None, redis_queue_name=None):
    try:

        threat_feeds = list()
        url = None
        # create feed_instance objects
        for feed in feed_settings:
            log.debug("Processing %s" % feed['name'])
            log.debug("feed settings:\n %s" % feed)
            url = feed['url'] 
            #log.info("Checking state of elasticsearch database") 
            #el_result = check_elasticsearch(feed)
            #return
            feed_instance = None
            if 'malwaredomains' in feed['name'] and feed['enabled']:
                feed_instance = Malwaredomains(feed['url'],
                         proxy_settings['enable'], proxy_settings['host'], proxy_settings['port'],
                         proxy_settings['user'],proxy_settings['password'], proxy_settings['auth'])
                log.debug("Feed: %s will be downloaded(refreshed) at an interval of %s"%(feed['name'], feed['period'] ))

            elif 'feodotracker' in feed['name'] and feed['enabled']:
                feed_instance = Feodo_tracker(feed['url'],
                         proxy_settings['enable'], proxy_settings['host'], proxy_settings['port'],
                         proxy_settings['user'],proxy_settings['password'], proxy_settings['auth'])
                log.debug("Feed: %s will be downloaded(refreshed) at an interval of %s"%(feed['name'], feed['period'] ))

            elif 'zeustracker' in feed['name'] and feed['enabled']:
                feed_instance = Zeus_tracker(feed['url'],
                         proxy_settings['enable'], proxy_settings['host'], proxy_settings['port'],
                         proxy_settings['user'],proxy_settings['password'], proxy_settings['auth'])
                log.debug("Feed: %s will be downloaded(refreshed) at an interval of %s"%(feed['name'], feed['period'] ))

            elif 'sslblacklist' in feed['name'] and feed['enabled']:
                feed_instance = Abuse_ssh_blacklist(feed['url'],
                         proxy_settings['enable'], proxy_settings['host'], proxy_settings['port'],
                         proxy_settings['user'],proxy_settings['password'], proxy_settings['auth'])
                log.debug("Feed: %s will be downloaded(refreshed) at an interval of %s"%(feed['name'], feed['period'] ))
                
            elif 'yoyo_adware' in feed['name'] and feed['enabled']:
                feed_instance = Yoyo_adware(feed['url'],
                         proxy_settings['enable'], proxy_settings['host'], proxy_settings['port'],
                         proxy_settings['user'],proxy_settings['password'], proxy_settings['auth'])
                log.debug("Feed: %s will be downloaded(refreshed) at an interval of %s"%(feed['name'], feed['period'] ))

            if feed_instance:
                # process the feed data to generate csv and yaml files containining malicious ip/domains 
                log.info("Download and processing feed - %s"%feed['name'])  
                feed_instance.process_feed(feed) 
                log.info("Feed - %s is processed successfully."%feed['name'])  

        #for feed in threat_feeds:
        #    feed.process_feed(output_type='csv',output_file='ttt.csv')	
            #job_result = redis_connection.enqueue_at(datetime.datetime.utcnow(),feed['feed_task'].process_feed, output_type='csv', output_file='ttt.csv')
            #logger.info("Threat feed - %s update is now submitted as a job to Job Scheduler with id %s." %('malwaredomains',job_result.id))  

    except Exception,exc:
        log.error("Error while downloading and processing threat intelligence feed %s  - %s" %(url,exc.message), exc_info = True) 

def cmd_options():

    args = None
    try:
        # good tutorial on argparse - http://pymotw.com/2/argparse/
        parser = argparse.ArgumentParser(description=""" This script reads ip/domain information
                 from threat intelligence feeds and generates csv/yaml files that can be used in conjunction with Bro/ELK stack
                 for tracking malicious activities. It also inserts this information in Elasticsearch database to build a malware ip/domain repository.""")

        parser.add_argument('--config', required=True, help='full path of yaml file containing settings information', dest='config_file')

        args, unknown = parser.parse_known_args()

    except Exception,exc :
        log.error("Error while parsing command line arguments! - %s" % exc.message, exc_info=True)
    return args

def main():

    try:
        # read command line arguments
        cmd_args = cmd_options()

        if not os.path.isfile(cmd_args.config_file):
            log.error(" The file %s containing configuration information is not present. Kindly re-check the file path and try again."% cmd_args.config_file)
            sys.exit(1)

        # read yaml configurations
        feed_settings, redis_settings, proxy_settings = get_configuration(cmd_args.config_file)

        # setup redis
        redis_con = None
    
        #enter geo databases in sequence - country db, city db and asn db 
        geo_instance = Geoip_mapping (os.path.join(os.path.sep,os.getcwd(),'GeoDB','GeoIP.dat'),
                                      os.path.join(os.path.sep,os.getcwd(),'GeoDB','GeoLiteCity.dat'),
                                      os.path.join(os.path.sep,os.getcwd(),'GeoDB','GeoIPASNum.dat'))
                                      
        country_name,country_abbr =  geo_instance.find_country('8.8.8.8')  
        log.debug("Checking Maxmind database..")
        log.debug("Country name: {} Country abbreviation: {}".format(country_name, country_abbr)) 
        log.debug("Checking of Maxmind database is over.")
  
        #redis_con = setup_redis(redis_settings['queue_name'],redis_settings['host'], redis_settings['port'])

        download_feeds(feed_settings, proxy_settings, redis_con, redis_settings['queue_name'])  

    except Exception,exc:
        log.error("Error while getting threat feeds information - %s"%exc.message, exc_info=True)

if __name__ == "__main__":
    main()
    sys.exit(1)
