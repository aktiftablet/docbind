"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
const app_js_1 = require("./app.js");
const repository_js_1 = require("./db/repository.js");
__exportStar(require("./app.js"), exports);
__exportStar(require("./crypto/envelope.js"), exports);
__exportStar(require("./db/repository.js"), exports);
__exportStar(require("./storage/storage.js"), exports);
__exportStar(require("./cache/redis.js"), exports);
const isDirectRun = process.argv[1]?.endsWith('src/index.ts') ||
    process.argv[1]?.endsWith('dist/index.js');
if (isDirectRun) {
    const port = Number(process.env.PORT || 4000);
    const { app } = (0, app_js_1.createApp)();
    app.listen(port, () => {
        console.log(`[DocBind API] Listening on http://localhost:${port}`);
        console.log(`[DocBind API] Default Dev API Key: ${repository_js_1.InMemoryRepository.DEFAULT_API_KEY}`);
    });
}
//# sourceMappingURL=index.js.map