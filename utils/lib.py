import logging

# So important B) would like to use it more but sigh idk maybe later
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class Dummy:
        def __getattr__(self, name): return ""
    Fore = Style = Dummy()


class ColoredFormatter(logging.Formatter):

    LOGGER_COLORS = {
        'FarfallePoisoner': Fore.CYAN,
        'PacketHandler': Fore.GREEN,
        'ARPSpoofer': Fore.YELLOW,
        'DNSSpoofer': Fore.MAGENTA,
        'NDPSpoofer': Fore.BLUE,
        'SSLStripper': Fore.RED,
        'NetworkScanner': Fore.WHITE,
    }

    LEVEL_COLORS = {
        'DEBUG': Fore.BLUE,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        if HAS_COLOR:
            # Color logger
            logger_color = self.LOGGER_COLORS.get(record.name, Fore.WHITE)
            record.name = f"{logger_color}{record.name}{Style.RESET_ALL}"

            # Color level
            level_color = self.LEVEL_COLORS.get(record.levelname, '')
            record.levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"

            # Color message
            record.msg = f"{logger_color}{record.msg}{Style.RESET_ALL}"

        return super().format(record)
