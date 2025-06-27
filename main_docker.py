#!/usr/bin/env python3
"""
Honeypot System - Docker Entry Point
====================================

This script launches the honeypot system in Docker with Docker-specific settings.
"""

# Import Docker settings instead of regular settings
import settings_docker as settings

# Now import and run the main function
if __name__ == "__main__":
    from main import main
    main() 