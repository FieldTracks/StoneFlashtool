# StoneFlashtool
This is a backend tool for flashing the `JellingStone` firmware to devices (ESP32). It's designed to be run on a Raspberry Pi and communicates (receiving commands / posting status) via an MQTT broker. The corresponding frontend can be found in the `fieldmon` repository.

This repository is part of the [Fieldtracks](https://fieldtracks.org/) project, which aims at creating a tracking system to be used in field exercises by relief organizations.

## Usage
1) Setup [esp-idf](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/#get-started-get-esp-idf) and make sure the environment variable `IDF_PATH` is set correctly
2) Install python dependencies: `pip3 install -r requirements.txt`
3) Copy and edit the default config file: `cp config-example.ini config.ini`
4) Run the script: `./flashtool.py config.ini`

## License
This file is part of StoneFlashtool - (C) The Fieldtracks Project

    StoneFlashtool is distributed under the civilian open source license (COSLi). Military usage is forbidden.

    You should have received a copy of COSLi along with StoneFlashtool.
    If not, please contact info@fieldtracks.org
