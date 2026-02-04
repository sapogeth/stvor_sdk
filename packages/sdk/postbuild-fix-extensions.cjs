// postbuild-fix-extensions.cjs
// Заменяет импорты без .js на .js в dist/*.js для ESM совместимости
const fs = require('fs');
const path = require('path');

const distDir = path.join(__dirname, 'dist');

function fixFile(filePath) {
  let code = fs.readFileSync(filePath, 'utf8');
  // Заменить только локальные импорты без расширения на .js
  code = code.replace(/(from ['"]\.\/?[\w\/-]+)(['"])/g, (m, p1, p2) => {
    if (p1.endsWith('.js')) return m;
    return p1 + '.js' + p2;
  });
  fs.writeFileSync(filePath, code);
}

fs.readdirSync(distDir).forEach(f => {
  if (f.endsWith('.js')) fixFile(path.join(distDir, f));
});
