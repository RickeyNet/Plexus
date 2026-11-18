"""APC Smart-UPS behind an APC Network Management Card (NMC2 / NMC3).

  ``firmware``  - UPS firmware file names (``SRT1025UPS_15-0.enc``), the
                  per-UPS-ID update rules and the update plan / pre-checks
  ``nmc_cli``   - parsing of the NMC command line output (``upsabout``,
                  ``about``, ``alarmcount``, ``upsfwupdate``) and the commands
  ``upgrade``   - the Upgrades tool phases for UPS devices (SSH CLI + SCP)
  ``snmp``      - the PowerNet-MIB state the monitoring poll reads (battery,
                  output, identity) and the built-in UPS alerts
"""
