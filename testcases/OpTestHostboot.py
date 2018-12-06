#!/usr/bin/python2
# OpenPOWER Automated Test Project
#
# Contributors Listed Below - COPYRIGHT 2017
# [+] International Business Machines Corp.
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

'''
OpTestHostboot: Hostboot checks
-------------------------------

Perform various hostboot validations and checks
'''

import unittest
import logging
import pexpect
import time
import string

import OpTestConfiguration
import OpTestLogger
from common.OpTestSystem import OpSystemState
from common.Exceptions import UnexpectedCase

log = OpTestLogger.optest_logger_glob.get_logger(__name__)

class OpTestHostboot(unittest.TestCase):
    '''
    OpTestHostboot class

    Purpose of this class is to sniff test the boot to catch
    any platform errors, we may encounter other issues so
    also catch those to surface as well.

    This test should properly set the state to UNKNOWN_BAD if
    applicable so that this test can be combined with any other
    tests and can appropriately recover.

    '''
    @classmethod
    def setUpClass(cls):
      conf = OpTestConfiguration.conf
      if conf.args.bmc_type in ['qemu', 'mambo']:
          raise unittest.SkipTest("QEMU/Mambo running so skipping tests")
      cls.cv_SYSTEM = conf.system()
      cls.my_connect = None
      cls.good_watermark = 15
      cls.threshold_attempts = 3

    def setUp(self, my_connect='ipmi'):
      if self.my_connect == 'host':
        self.my_console = self.cv_SYSTEM.host().get_ssh_connection()
      else:
        self.my_console = self.cv_SYSTEM.console
      # enable the console to be acquired non-obtrusively
      # console will not attempt to get prompts setup, etc
      # unblock to allow setup_term during get_console
      self.block_setup_term = 0
      self.cv_SYSTEM.console.enable_setup_term_quiet()
      self.pty = self.cv_SYSTEM.console.get_console()
      self.cv_SYSTEM.console.disable_setup_term_quiet()
      self.error = False
      self.count = self.threshold_attempts
      self.target = None

    def callback_general(self, **kwargs):
        # These are the main focus of this test
        log.debug("callback_general")
        default_vals = {'my_r': None,
                        'value': None,
                        'before': None,
                        'after': None}
        for key in default_vals:
          if key not in kwargs.keys():
            kwargs[key] = default_vals[key]
        combo_io = kwargs['before'] + kwargs['after']
        self.snippet_list.append("Snippet #{}".format(self.snippet_count))
        self.snippet_list += combo_io.replace("\r\r\n","\n").splitlines()
        self.snippet_count += 1
        self.error = True
        self.count -= 1

    def callback_hb(self, **kwargs):
        # just a watermarker
        log.debug("callback_hb")

    def callback_skiboot(self, **kwargs):
        # just a watermarker
        log.debug("callback_skiboot")

    def callback_occ(self, **kwargs):
        # just a watermarker
        log.debug("callback_occ")

    def callback_skiboot_assert(self, **kwargs):
        # Catch these and fail the test
        log.debug("callback_skiboot_assert")
        default_vals = {'my_r': None,
                        'value': None,
                        'before': None,
                        'after': None}
        for key in default_vals:
          if key not in kwargs.keys():
            kwargs[key] = default_vals[key]
        self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
        self.cv_SYSTEM.sys_sel_elist(dump=True)
        skiboot_exception = UnexpectedCase(state="SniffTest Skiboot Assert",
            message="We hit the callback_skiboot_assert value={}"
            .format(kwargs['value']))
        raise skiboot_exception

    def callback_xmon(self, **kwargs):
        # Catch these and fail the test
        log.debug("callback_xmon")
        default_vals = {'my_r': None,
                        'value': None,
                        'before': None,
                        'after': None}
        for key in default_vals:
          if key not in kwargs.keys():
            kwargs[key] = default_vals[key]
        xmon_value = kwargs['value']
        self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
        time.sleep(2)
        self.pty.sendline("t")
        time.sleep(3)
        rc = self.pty.expect([".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        xmon_backtrace = self.pty.after
        self.pty.sendline("r")
        time.sleep(3)
        rc = self.pty.expect([".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        xmon_registers = self.pty.after
        self.pty.sendline("S")
        time.sleep(5)
        rc = self.pty.expect([".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        xmon_special_registers = self.pty.after
        self.pty.sendline("e")
        time.sleep(5)
        rc = self.pty.expect([".*mon> ", pexpect.TIMEOUT, pexpect.EOF], timeout=10)
        xmon_exception_registers = self.pty.after
        self.cv_SYSTEM.sys_sel_elist(dump=True)
        my_msg = ('We hit the xmon_callback with \"{}\" backtrace=\n{}\n'
                  ' registers=\n{}\n special_registers=\n{}\n'
                  ' exception_registers=\n{}\n'
                  .format(xmon_value,
                  xmon_backtrace,
                  xmon_registers,
                  xmon_special_registers,
                  xmon_exception_registers))
        xmon_exception = UnexpectedCase(state="SniffTest XMON", message=my_msg)
        raise xmon_exception

    def callback_guard(self, **kwargs):
        # Catch these and fail the test
        log.debug("callback_guard")
        default_vals = {'my_r': None,
                        'value': None,
                        'before': None,
                        'after': None}
        for key in default_vals:
          if key not in kwargs.keys():
            kwargs[key] = default_vals[key]
        combo_io = kwargs['before'] + kwargs['after']
        self.snippet_list.append("Snippet #{}".format(self.snippet_count))
        self.snippet_list += combo_io.replace("\r\r\n","\n").splitlines()
        self.snippet_count += 1
        self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
        self.cv_SYSTEM.sys_sel_elist(dump=True)
        guard_exception = UnexpectedCase(state="SniffTest GUARD",
            message="We hit the callback_guard value={}\n{}"
            .format(kwargs['value'], ('\n'.join(f for f in self.snippet_list))))
        raise guard_exception

    def SniffTest(self):
      '''Perform sniff test for platform errors
      '''
      self.expect_table = {
          'Error reported by .* PLID .*===': self.callback_general,
          'SBE starting hostboot' : self.callback_hb,
          'OPAL skiboot' : self.callback_skiboot,
#          'OCCs are now running' : self.callback_occ,
          'OCCs are now running' : self.callback_skiboot,
          'Aborting!' : self.callback_skiboot_assert,
          'mon> ' : self.callback_xmon,
          'System shutting down with error status .*' : self.callback_guard,
          }
      base_seq = [pexpect.TIMEOUT, pexpect.EOF]
      expect_seq = list(base_seq) # we want a *copy*
      expect_seq = expect_seq + list(sorted(self.expect_table.keys()))
      self.snippet_list = []
      self.snippet_count = 1
      if self.target == 'os':
          self.cv_SYSTEM.sys_set_bootdev_no_override()
      else:
          self.cv_SYSTEM.sys_set_bootdev_setup()
      log.debug("SniffTest System Power Off")
      self.cv_SYSTEM.sys_power_off()
      self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
      rc = int(self.cv_SYSTEM.sys_wait_for_standby_state())
      if rc != 0:
          log.debug("SniffTest sys_wait_for_standby_state rc={},"
                    " needs investigation".format(rc))
          self.assertTrue(False,
                          "SniffTest unable to confirm power off"
                          " from sys_wait_for_standby_state,"
                          " needs investigation, rc={}"
                          .format(rc))
      log.debug("SniffTest System Power On")
      self.cv_SYSTEM.sys_power_on()
      counter = 0
      # get a new pexpect buffer in case stale
      self.cv_SYSTEM.console.enable_setup_term_quiet()
      self.pty = self.cv_SYSTEM.console.connect()
      self.cv_SYSTEM.console.disable_setup_term_quiet()
      while self.count != 0:
          rc = self.pty.expect(expect_seq, timeout=30)
          log.debug("SniffTest rc={} expect_seq={}".format(rc, expect_seq))
          log.debug("SniffTest before=\"{}\"\nSniffTest after=\"{}\""
                    .format(self.pty.before, self.pty.after))
          # if we have a hit on the string process it
          if (rc + 1) in range(len(base_seq) + 1, len(expect_seq) + 1):
              # if there is a handler callback
              if self.expect_table[expect_seq[rc]]:
                  try:
                      self.expect_table[expect_seq[rc]](my_r=rc,
                          value=expect_seq[rc],
                          before=self.pty.before,
                          after=self.pty.after)
                  except UnexpectedCase as u:
                      # these will fail the test
                      log.debug("SniffTest handler UnexpectedCase u={}"
                                .format(u))
                      self.assertTrue(False,
                                      "SniffTest handler encountered a failure"
                                      " which needs investigation\n"
                                      "UnexpectedCase={}"
                                      .format(u))
                  except Exception as e:
                      # these will error the test
                      log.debug("SniffTest Exception raised Exception={}"
                                .format(e))
                      # if a callback handler raised an exception, re-raise
                      raise e
          if self.error:
              self.error = False
              log.debug("RESETTING Powering Off System")
              self.cv_SYSTEM.sys_power_off()
              self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
              rc = int(self.cv_SYSTEM.sys_wait_for_standby_state())
              if rc != 0:
                  log.debug("ERROR sys_wait_for_standby_state rc={}, "
                            "needs investigation".format(rc))
                  self.assertTrue(False,
                                 "SniffTest ERROR unable to confirm power off"
                                 " from sys_wait_for_standby_state,"
                                 " needs investigation, rc={}"
                                 .format(rc))
              log.debug("RESETTING Powering On System")
              self.cv_SYSTEM.sys_power_on()
          else:
              log.debug("SniffTest pulse counter={} max={}"
                        .format(counter, self.good_watermark))
              if counter > self.good_watermark:
                  log.debug("SniffTest watermark reached={}, "
                            "if you are not at the login or Petitboot menu "
                            "investigate making the good_watermark longer"
                            .format(counter))
                  break
              else:
                  counter += 1
      if self.count == 0:
          log.debug("SniffTest FAILED, get_state={}"
                    .format(self.cv_SYSTEM.get_state()))
          # set to UNKNOWN_BAD for next guy
          self.cv_SYSTEM.set_state(OpSystemState.UNKNOWN_BAD)
          return False
      else:
          log.debug("SniffTest SUCCESS, get_state={}"
                    .format(self.cv_SYSTEM.get_state()))
          return True

    def HostChecks(self):
      '''Sniff test booting to Host OS for any platform errors
      '''
      log.debug("Starting SniffTest HostChecks")
      self.target = 'os'
      success = self.SniffTest()
      if success:
          log.debug("SniffTest success goto OS")
          try:
              self.cv_SYSTEM.goto_state(OpSystemState.OS)
          except UnexpectedCase as u:
              # these will fail the test
              log.debug("HostChecks UnexpectedCase u={}"
                        .format(u))
              self.assertTrue(False,
                              "HostChecks encountered a failure"
                              " which needs investigation\n"
                              "UnexpectedCase={}"
                              .format(u))
      else:
          new_list = list(filter(None, self.snippet_list))
          self.assertTrue(False, "We reached the limit on how many"
              " errors detected during boot: \"{}\"\n{}"
              .format(self.threshold_attempts,
              ('\n'.join(f for f in new_list))))

    def PetitbootChecks(self):
      '''Sniff test booting to Petitboot for any platform errors
      '''
      log.debug("Starting SniffTest PetitbootChecks")
      self.target = 'petitboot'
      success = self.SniffTest()
      if success:
          log.debug("SniffTest success goto PS")
          try:
              self.cv_SYSTEM.goto_state(OpSystemState.PETITBOOT_SHELL)
          except UnexpectedCase as u:
              # these will fail the test
              log.debug("PetitbootChecks UnexpectedCase u={}"
                        .format(u))
              self.assertTrue(False,
                              "PetitbootChecks encountered a failure"
                              " which needs investigation\n"
                              "UnexpectedCase={}"
                              .format(u))
      else:
          new_list = list(filter(None, self.snippet_list))
          self.assertTrue(False, "We reached the limit on how many"
              " errors detected during boot: \"{}\"\n{}"
              .format(self.threshold_attempts,
              ('\n'.join(f for f in new_list))))

class SkirootBasicCheck(OpTestHostboot, unittest.TestCase):
    '''Class for Skiroot based tests
       This class allows --run testcases.OpTestHostboot.SkirootBasicCheck
    '''
    def setUp(self):
      super(SkirootBasicCheck, self).setUp()

    def runTest(self):
      self.PetitbootChecks()

class HostBasicCheck(OpTestHostboot, unittest.TestCase):
    '''Class for Host based tests
       This class allows --run testcases.OpTestHostboot.HostBasicCheck
    '''
    def setUp(self):
      self.my_connect = 'host'
      super(HostBasicCheck, self).setUp()

    def runTest(self):
      self.HostChecks()

def skiroot_suite():
    '''Function used to prepare a test suite (see op-test)
       This allows --run-suite hostboot
       Tests run in order
    '''
    tests = ['PetitbootChecks']
    return unittest.TestSuite(map(SkirootBasicCheck, tests))

def skiroot_full_suite():
    '''Function used to prepare a test suite (see op-test)
       This allows --run-suite hostboot
       Tests run in order
    '''
    tests = ['PetitbootChecks']
    return unittest.TestSuite(map(SkirootBasicCheck, tests))

def host_suite():
    '''Function used to prepare a test suite (see op-test)
       This allows --run-suite hostboot
       Tests run in order
    '''
    tests = ['HostChecks']
    return unittest.TestSuite(map(HostBasicCheck, tests))

def host_full_suite():
    '''Function used to prepare a test suite (see op-test)
       This allows --run-suite hostboot
       Tests run in order
    '''
    tests = ['HostChecks']
    return unittest.TestSuite(map(HostBasicCheck, tests))
