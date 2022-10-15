from rpi_node import RPI4Node


if __name__ == "__main__":

    rpi = RPI4Node(
        'RPI_test_node', config_path='/config/config.ini', debug=False)

    rpi.startup()
    rpi.loop()
