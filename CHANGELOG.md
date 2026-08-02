# Changelog

All notable changes to certdoctor that a user would notice when running the program.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file records only what a person would notice by running the program. Internal structure, guards, CI and measurements are kept in a separate technical changelog that is not part of this repository, so nothing here should be read as the whole story of a change.

## [Unreleased]

Nothing diagnosable yet, and there has been no release.

There is now a `certdoctor` command, but it assesses nothing. It writes one line to the log channel saying so, writes nothing at all to the report channel, and ends with the exit code that means "could not assess". It exists so that the release build has an artefact to check, not because there is anything to run it against.
