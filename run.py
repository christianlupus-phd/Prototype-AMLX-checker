#!/bin/env python

import coloredlogs, logging
import sys

import amlx_prototype

verbosityLevel = {
    0: logging.WARN,
    1: logging.INFO,
}
coloredlogs.install(level=verbosityLevel.get(amlx_prototype.cli.args.verbose, logging.DEBUG), stream=sys.stdout)
logging.basicConfig(level=logging.NOTSET, stream=sys.stdout)
logger = logging.getLogger('main')

logger.debug("Found CLI parameters: %s", amlx_prototype.cli.args)

workerMap = {
    'bootstrap': amlx_prototype.bootstrapper.Bootstrapper,
    'sign': amlx_prototype.signer.Signer,
    'check': amlx_prototype.checker.Checker,
}

worker = workerMap[amlx_prototype.cli.args.cmd](amlx_prototype.cli.args)
worker.run()
