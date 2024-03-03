from setuptools import find_packages,setup
from typing import List

"""HYPEN_E_DOT='-e .'

def get_requirements(file_path:str)->List[str]:
    requirements=[]
    with open(file_path) as file_obj:
        requirements=file_obj.readlines()
        requirements=[req.replace("\n","") for req in requirements]

        if HYPEN_E_DOT in requirements:
            requirements.remove(HYPEN_E_DOT)

    return requirements"""

setup(
    name='IoTShieldClientApp',
    version='0.0.1',
    author='Sibasis Pradhan',
    author_email='2021sc04667@wilp.bits-pilani.ac.in',
    install_requires=["pandas","numpy","scikit-learn"],
    packages=find_packages()
)