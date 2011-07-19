
# vim: set ts=2 sw=2 tw=99 noet:
import sys
import ambuild.runner as runner

run = runner.Runner()
run.options.usage = '%prog [options] [job list]'
run.options.add_option('-l', '--list-jobs', action='store_true', dest='list', help='print list of jobs')
run.Build()
		