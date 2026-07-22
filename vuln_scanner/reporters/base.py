from abc import ABC, abstractmethod


class BaseReporter(ABC):

    @abstractmethod
    def generate(self, results, output_path):
        pass
