# Yeznsap v4.5 — Security Matrix

هذا الملف يذكر ما هو موجود فعليًا في الكود، وليس قائمة تسويقية.

## Encryption

| الميزة | الحالة | التنفيذ |
|---|---|---|
| TLS أثناء النقل | Deployment | يجب استخدام HTTPS في الإنتاج؛ HSTS يفعّل مع `NODE_ENV=production`. |
| At-Rest Encryption | ✅ | `data/store.enc` عبر AES-256-GCM. |
| Direct-message E2EE | ✅ | النص يُشفّر في العميل بـ AES-256-GCM؛ الخادم يخزن Ciphertext. |
| Conversation-key wrapping | ✅ | مفتاح 256-bit لكل محادثة، مغلف RSA-OAEP 3072 لكل مشارك. |
| Signed key establishment | ✅ | منشئ المحادثة يوقّع `keyId + participants + SHA-256(chatKey)` بمفتاح ECDSA P-256؛ العميل والخادم يتحققان من التوقيع. |
| Recovery phrase server-blind | ✅ للحسابات v4.5 | الكلمات تتولد محليًا ولا تقبلها API. |
| Private identity key backup | ✅ | مفاتيح RSA وECDSA الخاصة داخل Bundle مشفر محليًا AES-256-GCM بمفتاح PBKDF2-SHA256 مشتق من كلمات الاسترداد. |
| Key fingerprint / TOFU | ✅ | SHA-256 fingerprint ظاهر في المحادثة ومثبت في IndexedDB. |
| Signal Protocol / Double Ratchet | ❌ | غير منفذ؛ لا تدّع Signal/PFS. |
| Group Sender Keys | ❌ | لا توجد مجموعات E2EE بعد. |
| Media E2EE | ❌ | النص المباشر فقط في v4.5. |

## Authentication

- Username فقط كمعرف أساسي.
- Recovery key جديد: 16 كلمة، 128-bit selection entropy.
- المتصفح يشتق `authSecret = SHA-256(domain || normalized recovery phrase)` ويرسل الـauthSecret بدل الكلمات.
- الخادم يطبق scrypt + salt + pepper على `authSecret`.
- TOTP مع replay tracking وBackup Codes.
- PIN اختياري للجلسة.
- Device-bound opaque sessions.

## Session Security

- Cookies: HttpOnly + SameSite=Strict + Secure في الإنتاج.
- `__Host-` prefix في الإنتاج.
- Idle timeout افتراضي 30 دقيقة.
- Absolute timeout افتراضي 7 أيام.
- حد أجهزة افتراضي 5.
- إنهاء جلسة جهاز آخر أو كل الجلسات الأخرى.
- CSRF token وOrigin/Sec-Fetch checks للطلبات الحساسة.

## E2EE Threat Boundaries

الخادم لا يحتاج النص الواضح لفك الرسائل الجديدة. مع ذلك:

1. الخادم يرى Metadata للمحادثة.
2. الخادم يوزع Public Keys؛ TOFU يكشف تغيّر المفتاح بعد تثبيته، لكن أول اتصال يحتاج مقارنة Fingerprint خارج التطبيق لمقاومة خادم خبيث يبدل الهوية منذ البداية.
3. اتفاق مفتاح المحادثة موقّع بـECDSA، لذلك لا يستطيع الخادم تبديل Envelope/Chat Key قائم بصمت من دون كسر التوقيع؛ هذا لا يحل مشكلة انتحال الهوية عند **أول اتصال** إذا لم تُقارن البصمة خارج التطبيق.
4. لا يوجد Double Ratchet؛ اختراق مفتاح المحادثة يمكن أن يؤثر على تاريخ المحادثة المشفر المرتبط به.
5. جهاز مستخدم مخترق أو XSS قادر على تنفيذ كود موثوق داخل نفس Origin يمكنه الوصول إلى النص بعد فك التشفير. CSP تقلل الخطر لكنها لا تحول الجهاز المخترق إلى جهاز آمن.
6. مفاتيح الهوية الخاصة المحلية محفوظ كـCryptoKey في IndexedDB أثناء الجلسات المستمرة؛ عند Logout الصريح تتم إزالة هوية الجهاز المحلية، بينما تبقى Trust Pins لحماية كشف تغير مفاتيح الأصدقاء.

## Attack Prevention

- Rate limiting على التسجيل/الدخول/الرسائل والعمليات الحساسة.
- KDF concurrency queue لمنع استنزاف RAM/CPU عبر scrypt.
- Input size limits.
- CSP بدون `unsafe-inline` أو `unsafe-eval`.
- UI يضع المحتوى غير الموثوق عبر `textContent`.
- لا يوجد SQL في النسخة الحالية.
- Message endpoint لا يقبل Plaintext `text` في v4.5.

## Data Protection

- `.env` و`data/store.enc` غير مرفوعين إلى Git.
- حذف الحساب يحذف المستخدم، الجلسات والمحادثات المرتبطة به، ثم يرسل Clear-Site-Data للمتصفح.
- Data export موجود لكنه ليس Recovery backup للمحادثات.
- GDPR support جزئي هندسيًا؛ الامتثال الكامل يحتاج سياسات وعمليات قانونية وتشغيلية.

## Not Yet Implemented

- Signal Protocol / Double Ratchet / PQXDH.
- Group E2EE / Sender Keys.
- E2EE media and calls.
- Passkeys/WebAuthn.
- Certificate Pinning أو Root/Jailbreak detection، لأنها تحتاج Client Native مناسب.
- Independent penetration test/security audit — مطلوب قبل الإنتاج الحقيقي.
