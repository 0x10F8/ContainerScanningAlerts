# -*- coding: utf-8 -*-
import docker
import json


class GrypeScanner:
    """
    Grype scanner for Docker images.
    This class uses the Grype scanner to scan Docker images for vulnerabilities.
    """

    # Use the latest Grype scanner image
    GRYPE_SCANNER_IMAGE = "anchore/grype:latest"

    def __init__(self, image: str, version="latest"):
        """
        Initialize the GrypeScanner with the image and version to scan.
        Args:
            image (str): The Docker image to scan.
            version (str): The version of the Docker image to scan. Defaults to "latest".
        """
        self.image = image
        self.version = version
        

    def scan_image(self) -> dict:
        """
        Scan the Docker image using the Grype scanner.
        Returns:
            dict: The results of the scan in a JSON dict.
        """
        client = docker.from_env()
        try:
            results = client.containers.run(self.GRYPE_SCANNER_IMAGE, command=f"{self.image}:{self.version} -o json", auto_remove=True)
            client.close()
            return json.loads(str(results, encoding="utf-8"))
        except docker.errors.ContainerError as e:
            print(f"Error scanning image {self.image}:{self.version} - {e}")
            return {}
        except docker.errors.ImageNotFound as e:
            print(f"Image not found: {self.image}:{self.version} - {e}")
            return {}
        except docker.errors.APIError as e:
            print(f"API error: {e}")
            return {} 