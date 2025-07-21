#process and system
require 'open3'
require 'etc'
require 'fileutils'
#network
require 'socket'
require 'timeout'
require 'json'
require 'csv'
require 'yaml'
require 'digest'
# Threading e timing
require 'thread'
require 'time'
# CLI e options
require 'optparse'
#for logging
require "logger"
require 'syslog'

#intrusion detection system
class SecurityWatcher
 def initialize
   @logger = Logger.new(STDOUT)
   @logger.level = Logger::DEBUG
   @logger.datetime_format = "%Y-%m-%d %H:%M:%S"
   @logger.formatter = proc do |severity, datetime, progname, msg|
     "#{datetime} - #{severity}: #{msg}\n"
   end
   @syslog = Syslog.open('SecurityWatcher', Syslog::LOG_PID | Syslog::LOG_CONS, Syslog::LOG_USER)
   @syslog.log(Syslog::LOG_INFO, "SecurityWatcher initialized")
 end
def start
        log("Starting SecurityWatcher")
        process_monitor = ProcessMonitor.new
        alert_manager = AlertManager.new
        intrusion_detector = IntrusionDetectionSystem.new
        process_monitor.monitor_processes
        intrusion_detector.detect_intrusions
        log("SecurityWatcher started successfully")
    end

 def log(message, level = Logger::INFO)
   @logger.add(level, message)
   @syslog.log(Syslog::LOG_INFO, message)
 end

 class ProcessMonitor
   def initialize
     @logger = Logger.new(STDOUT)
     @logger.level = Logger::DEBUG
     @logger.datetime_format = "%Y-%m-%d %H:%M:%S"
     @logger.formatter = proc do |severity, datetime, progname, msg|
       "#{datetime} - #{severity}: #{msg}\n"
     end
   end

   def monitor_processes
     log("Starting process monitoring")
     begin
       processes = `ps aux`.split("\n")[1..-1]
       processes.each do |process|
         details = process.split(/\s+/, 11)
         pid = details[1]
         user = details[0]
         command = details[10]
         log("Process ID: #{pid}, User: #{user}, Command: #{command}")
       end
     rescue => e
       log("Error monitoring processes: #{e.message}", Logger::ERROR)
     end
     log("Process monitoring completed")
   end

   private

   def log(message, level = Logger::INFO)
     @logger.add(level, message)
   end
 end

 class AlertManager
   def initialize
     @logger = Logger.new(STDOUT)
     @logger.level = Logger::DEBUG
     @logger.datetime_format = "%Y-%m-%d %H:%M:%S"
     @logger.formatter = proc do |severity, datetime, progname, msg|
       "#{datetime} - #{severity}: #{msg}\n"
     end
   end

   def send_alert(message)
     log("Sending alert: #{message}")
     begin
       # send an alert via email or other means
       # For demonstration, we will just log it
       log("Alert sent: #{message}")
     rescue => e
       log("Error sending alert: #{e.message}", Logger::ERROR)
     end
   end

   private

   def log(message, level = Logger::INFO)
     @logger.add(level, message)
   end
 end

 class IntrusionDetectionSystem
   def initialize
     @logger = Logger.new(STDOUT)
     @logger.level = Logger::DEBUG
     @logger.datetime_format = "%Y-%m-%d %H:%M:%S"
     @logger.formatter = proc do |severity, datetime, progname, msg|
       "#{datetime} - #{severity}: #{msg}\n"
     end
   end

   def detect_intrusions
     log("Starting intrusion detection")
     begin
       suspicious_files = Dir.glob('/etc/*').select { |file| File.size(file) > 1000000 }
       suspicious_files.each do |file|
         log("Suspicious file detected: #{file}")
         FileUtils.chmod(0644, file) # Change permissions to read-only
         log("Permissions changed for: #{file}")
       end
     rescue => e
       log("Error during intrusion detection: #{e.message}", Logger::ERROR)
     end
     log("Intrusion detection completed")
   end

   private

   def log(message, level = Logger::INFO)
     @logger.add(level, message)
   end
 end
end

if __FILE__ == $0
  watcher = SecurityWatcher.new
  watcher.start
end
