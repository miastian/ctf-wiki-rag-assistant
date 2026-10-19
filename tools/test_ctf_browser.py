"""Browser checks using synthetic evidence and a mock model. No paid calls."""
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'artifacts'


def main():
    OUT.mkdir(exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel='msedge', headless=True)
        page = browser.new_page(viewport={'width':1440,'height':1000})
        errors=[];page.on('pageerror',lambda exc: errors.append(str(exc)))
        page.goto('http://127.0.0.1:8766');page.wait_for_load_state('networkidle')
        expect(page.locator('.brand')).to_contain_text('CTF 思路助手')
        import json
        from urllib.request import urlopen
        options = json.load(urlopen('http://127.0.0.1:8766/api/options'))
        if options.get('ready'):
            expect(page.locator('.library-note')).to_contain_text(f"{options['library']['documents']} 篇资料")
            page.screenshot(path=str(OUT/'ctf-real-ready.png'),full_page=True)
        else:
            expect(page.locator('.library-note')).to_contain_text('尚未构建导入')
            page.get_by_label('输入问题').fill('PNG 怎么分析？')
            expect(page.get_by_role('button',name='发送 ↑')).to_be_disabled()
            page.screenshot(path=str(OUT/'ctf-pending.png'),full_page=True)
        page.goto('http://127.0.0.1:8767');page.wait_for_load_state('networkidle')
        page.get_by_role('button',name='＋ 新建会话').click()
        page.get_by_label('输入问题').fill('工具提示 IHDR CRC error')
        page.get_by_role('button',name='发送 ↑').click()
        expect(page.locator('.source-list button').last).to_be_visible()
        page.get_by_label('查看引用 1').first.click()
        expect(page.locator('.evidence pre')).to_contain_text('IHDR')
        page.screenshot(path=str(OUT/'ctf-mock-evidence.png'),full_page=True)
        page.get_by_label('关闭引用').click()
        page.get_by_role('button',name='展开详细步骤',exact=True).click()
        expect(page.locator('.turn')).to_have_count(2)
        page.get_by_label('回答形式').select_option('checklist')
        page.get_by_label('输入问题').fill('第二点怎么检查？')
        page.get_by_role('button',name='发送 ↑').click()
        expect(page.locator('.answer-mode').last).to_have_text('检查清单')
        page.get_by_text('题目方向 · 全部',exact=True).click()
        page.locator('.filter-menu').get_by_label('Web',exact=True).check()
        page.get_by_text('题目方向 · 1 项',exact=True).click()
        page.get_by_label('输入问题').fill('换题，SQL 注入从哪开始？')
        page.get_by_role('button',name='发送 ↑').click()
        expect(page.locator('.turn')).to_have_count(4)
        page.get_by_label('查看引用 1').last.click()
        expect(page.locator('.evidence pre')).to_contain_text('SQL')
        page.get_by_label('关闭引用').click()
        page.reload();page.wait_for_load_state('networkidle')
        expect(page.locator('.turn')).to_have_count(4)
        expect(page.locator('.range')).to_contain_text('Web')
        page.get_by_role('button',name='清除筛选').click()
        page.get_by_label('输入问题').fill('CRC error 模拟失败')
        page.get_by_role('button',name='发送 ↑').click()
        expect(page.get_by_role('button',name='重试本轮')).to_be_visible()
        page.get_by_role('button',name='重试本轮').click()
        expect(page.locator('.turn')).to_have_count(6)
        expect(page.locator('.source-list').last).to_be_visible()
        page.set_viewport_size({'width':390,'height':844})
        page.screenshot(path=str(OUT/'ctf-mock-mobile.png'),full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.set_viewport_size({'width':1440,'height':1000})
        page.once('dialog',lambda dialog:dialog.accept())
        page.get_by_role('button',name='清空',exact=True).click()
        expect(page.locator('.turn')).to_have_count(0)
        page.once('dialog',lambda dialog:dialog.accept())
        page.get_by_role('button',name='删除',exact=True).click()
        assert not errors, errors
        browser.close()
    print('CTF UI ready-state and browser mock checks passed; this does not score real LLM answers.')


if __name__ == '__main__':
    main()
