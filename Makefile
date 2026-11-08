.PHONY: help test demo audit audit-strict report build lint clean install

PYTHON ?= python3

help:  ## 显示所有可用命令
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## 以可编辑模式安装（零运行时依赖）
	$(PYTHON) -m pip install -e .

test:  ## 运行全部单元测试
	$(PYTHON) -m unittest discover -s tests -v

demo:  ## 导出演示快照并审计
	$(PYTHON) -m mailproof demo > demo.zone
	$(PYTHON) -m mailproof audit demo.zone

audit:  ## 用默认基线审计示例快照
	$(PYTHON) -m mailproof audit examples/sample.zone

audit-strict:  ## 用严格基线审计示例快照
	$(PYTHON) -m mailproof audit examples/sample.zone --baseline strict

report:  ## 生成 HTML/SARIF/Markdown 三份报告
	$(PYTHON) -m mailproof audit examples/sample.zone --format html -o report.html
	$(PYTHON) -m mailproof audit examples/sample.zone --format sarif -o report.sarif
	$(PYTHON) -m mailproof audit examples/sample.zone --format markdown -o report.md

build:  ## 跨平台一键构建 wheel + SHA256（纯 Python，无额外依赖）
	$(PYTHON) scripts/build.py

lint:  ## 语法编译检查
	$(PYTHON) -m compileall -q mailproof tests scripts

clean:  ## 清理构建产物
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -f demo.zone report.html report.sarif report.md
