# vim: set ts=2 sw=2 tw=99 noet ft=python: 
import os, sys
import re
import subprocess

argv = sys.argv[1:]
if len(argv) < 2:
  sys.stderr.write('Usage: generate_header.py <source_path> <output_folder>\n')
  sys.exit(1)

SourceFolder = os.path.abspath(os.path.normpath(argv[0]))
OutputFolder = os.path.normpath(argv[1])

def run_and_return(argv):
  # Python 2.6 doesn't have check_output.
  if hasattr(subprocess, 'check_output'):
    text = subprocess.check_output(argv)
    if str != bytes:
      text = str(text, 'utf-8')
  else:
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, ignored = p.communicate()
    rval = p.poll()
    if rval:
      raise subprocess.CalledProcessError(rval, argv)
    text = output.decode('utf8')
  return text.strip()

def GetGHVersion():
	p = run_and_return(['hg', 'parent', '-R', SourceFolder])
	m = re.match('changeset:\s+(\d+):(.+)', p.stdoutText)
	if m == None:
		raise Exception('Could not determine repository version')
	return m.groups()

def GetGitVersion():
  revision_count = run_and_return(['git', 'rev-list', '--count', 'HEAD'])
  revision_hash = run_and_return(['git', 'log', '--pretty=format:%h:%H', '-n', '1'])
  shorthash, longhash = revision_hash.split(':')

  return revision_count, shorthash

rev = None
cset = None 
if os.path.exists(os.path.join(SourceFolder, '.hg')): # Mercurial repository
  rev, cset = GetGHVersion()
else: # Assume its a git repository
  rev, cset =  GetGitVersion()

productFile = open(os.path.join(SourceFolder, 'product.version'), 'r')
productContents = productFile.read()
productFile.close()
m = re.match('(\d+)\.(\d+)\.(\d+)(.*)', productContents)
if m == None:
	raise Exception('Could not detremine product version')
major, minor, release, tag = m.groups()

incFile = open(os.path.join(OutputFolder, 'version_auto.h'), 'w')
incFile.write("""
#ifndef _AUTO_VERSION_INFORMATION_H_
#define _AUTO_VERSION_INFORMATION_H_
#define SM_BUILD_TAG	 	\"{0}\"
#define SM_BUILD_UNIQUEID	\"{1}:{2}\" SM_BUILD_TAG
#define SM_VERSION			\"{3}.{4}.{5}\"
#define SM_FULL_VERSION		SM_VERSION SM_BUILD_TAG
#define SM_FILE_VERSION		{6},{7},{8},0
#endif /* _AUTO_VERSION_INFORMATION_H_ */
""".format(tag, rev, cset, major, minor, release, major, minor, release))
incFile.close()