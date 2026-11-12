async page => {
  // Synthetic transport only: this browser never launches Installer, sudo or a VPN.
  const receipts = [], requests = [];
  let state, pending;
  const check = (value, message) => { if (!value) throw Error(message); };
  await page.unroute('**/api/command');
  await page.route('**/api/command', async route => {
    const body = route.request().postDataJSON();
    if (['install_helper', 'remove_helper'].includes(body.command.type)) {
      requests.push({ type: body.command.type, locale: body.locale });
      check(!pending, 'duplicate component operation');
      pending = { route, id: body.id };
    } else {
      await route.fulfill({ json: { id: body.id, snapshot: state } });
    }
  });
  const finish = async error => {
    const { route, id } = pending;
    pending = undefined;
    await route.fulfill({ json: error ? { id, error } : { id, snapshot: state } });
  };
  for (const locale of ['en-US', 'pt-BR']) for (const theme of ['light', 'dark']) for (const width of [420, 280]) for (const kind of ['install', 'remove']) {
    const pt = locale === 'pt-BR';
    const action = kind === 'install' ? pt ? 'Instalar' : 'Install' : pt ? 'Remover' : 'Remove';
    const start = requests.length;
    state = { version: '0.1.0', demo: false, helper: kind === 'install' ? 'missing' : 'installed', vpns: [] };
    await page.evaluate(({locale, theme}) => localStorage.setItem('vpnt.preferences.v1', JSON.stringify({locale, theme})), {locale, theme});
    await page.setViewportSize({width, height:820});
    await page.reload();
    if (kind === 'remove') await page.getByRole('button', {name: pt ? 'Preferências' : 'Preferences', exact:true}).click();
    const opener = page.getByRole('button', {name:action, exact:true});
    await opener.click();
    const dialog = page.getByRole('dialog');
    await dialog.waitFor();
    check(requests.length === start, 'operation sent before confirmation');
    check((await dialog.textContent()).includes(pt ? 'mantidos' : 'kept'), 'preservation not explained');
    await page.keyboard.press('Escape');
    await dialog.waitFor({state:'hidden'});
    check(requests.length === start, 'cancel sent an operation');
    check(await opener.evaluate(el => el === document.activeElement), 'focus was not restored');
    await opener.click();
    await dialog.getByRole('button', {name:action, exact:true}).click();
    await page.waitForFunction(() => document.querySelector('dialog')?.getAttribute('aria-busy') === 'true');
    check(requests.length === start + 1, 'confirmation did not send exactly once');
    check(await dialog.getByRole('button', {name:pt ? 'Cancelar' : 'Cancel', exact:true}).isDisabled(), 'busy dialog can cancel locally');
    await page.keyboard.press('Escape');
    await page.keyboard.press('Enter');
    check(await dialog.isVisible() && requests.length === start + 1, 'pending dialog dismissed or replayed');
    const geometry = await dialog.evaluate(el => ({
      width: el.getBoundingClientRect().width,
      overflow: el.scrollWidth > el.clientWidth,
      focusInside: el.contains(document.activeElement),
      panelWidth: document.querySelector('#panel').getBoundingClientRect().width,
      pageOverflow: document.documentElement.scrollWidth > innerWidth,
      lang: document.documentElement.lang,
      dark: document.documentElement.classList.contains('dark'),
    }));
    check(!geometry.overflow && !geometry.pageOverflow && geometry.focusInside && geometry.lang === locale && geometry.dark === (theme === 'dark') && geometry.panelWidth === Math.min(320,width), JSON.stringify(geometry));
    await page.screenshot({path:`output/playwright/component-${locale}-${theme}-${width}-${kind}.png`,fullPage:true});
    state.componentOperation = 'settling';
    await finish('component_expired');
    await dialog.waitFor({state:'hidden'});
    await page.getByRole('alert').filter({hasText:pt ? 'prazo' : 'timed out'}).waitFor();
    await page.getByRole('status').filter({hasText:pt ? 'operação anterior' : 'previous operation'}).first().waitFor();
    if (kind === 'remove') check(await opener.isDisabled(), 'settling removal can be retried');
    else check(await opener.count() === 0, 'settling installation can be retried');
    check(requests.length === start + 1, 'timeout replayed automatically');
    await page.screenshot({path:`output/playwright/component-${locale}-${theme}-${width}-${kind}-settling.png`,fullPage:true});
    delete state.componentOperation;
    if (kind === 'install') await opener.waitFor();
    else await page.waitForFunction(() => !document.querySelector('button.danger')?.disabled);
    await opener.click();
    await dialog.getByRole('button', {name:action, exact:true}).click();
    await page.waitForFunction(() => document.querySelector('dialog')?.getAttribute('aria-busy') === 'true');
    state.helper = kind === 'install' ? 'installed' : 'missing';
    if (kind === 'install' && width === 420) state.vpns = [{
      profile: {id:'retained-fixture',name:'Retained fixture VPN',kind:'ssl',gateway:'vpn.example.com',username:'fixture',networks:[],port:443,certificate:'',probeHost:'192.0.2.1',probePort:8443,probeMethod:'tcp'},
      state:'off',hasPassword:true,hasPsk:false,log:[],
    }];
    await finish();
    await dialog.waitFor({state:'hidden'});
    if (kind === 'install' && width === 420) {
      await page.getByRole('heading', {name:'VPNs',exact:true}).waitFor({timeout:1500});
      await page.getByRole('button', {name:/^Retained fixture VPN:/}).waitFor();
    } else if (kind === 'install') await page.getByRole('heading', {name:pt ? 'Nova VPN' : 'New VPN',exact:true}).waitFor();
    else {
      await page.getByRole('heading', {name:pt ? 'Preferências' : 'Preferences',exact:true}).waitFor();
      await page.getByRole('button', {name:pt ? 'Instalar' : 'Install',exact:true}).waitFor();
      check(await page.getByRole('button', {name:action,exact:true}).count() === 0, 'removed component still has a removal action');
    }
    check(requests.length === start + 2 && requests.slice(start).every(r => r.locale === locale && r.type === `${kind}_helper`), 'wrong command or locale');
    receipts.push({locale,theme,width,kind,geometry,confirmed:true,canceledWithoutRequest:true,pendingRetained:true,timeoutNoReplay:true,successNavigation:true});
  }
  await page.unroute('**/api/command');
  return {receipts,requests,limits:'Isolated Chromium, synthetic component transport. No native tray/WKWebView, authorization, Installer, installation or VPN.'};
}
