# دليل نسخة التلفون (Mobile / Phone Application)

عندك **طريقتين** تحوّل بيهم CyberShield AI لتطبيق موبايل. الطريقة الأولى فورية ومجانية ومناسبة جدًا للبريزنتيشن، والتانية بتطلّع ملف `.apk` حقيقي.

---

## ⭐ الطريقة 1: تثبيت PWA على الموبايل (الأسرع والموصى بها)

التطبيق مبني كـ **PWA (Progressive Web App)** — يعني بيتثبّت على الموبايل ويشتغل ملء الشاشة زي أي تطبيق، بأيقونة على الشاشة الرئيسية، ومن غير متجر تطبيقات.

الموبايل بيحتاج يفتح الموقع عبر **HTTPS**. أسهل طريقة مجانية: ارفع الفولدر على **Netlify** أو **GitHub Pages** (خطوات تحت)، وبعدها افتح الرابط على الموبايل.

### أ) ارفع المشروع على الإنترنت مجانًا (Netlify — بالسحب والإفلات)
1. ادخل على [https://app.netlify.com/drop](https://app.netlify.com/drop)
2. **اسحب فولدر `CyberShield-AI` كله** وأفلته في الصفحة.
3. Netlify هيديك رابط HTTPS زي: `https://your-name.netlify.app`
4. افتح الرابط ده على موبايلك.

> بديل: GitHub Pages — اعمل repo، ارفع الملفات، فعّل Pages من Settings → Pages. (محتاج حساب GitHub)

### ب) ثبّت التطبيق على الموبايل
**على Android (Chrome):**
1. افتح الرابط في Chrome.
2. هتظهر رسالة **"Add to Home screen"** / **"Install app"** — اضغطها.
   - أو من القائمة (⋮) → **Install app** / **Add to Home screen**.
3. هتلاقي أيقونة **CyberShield AI** على شاشة الموبايل. افتحها → هتشتغل ملء الشاشة زي تطبيق حقيقي.

**على iPhone (Safari):**
1. افتح الرابط في **Safari**.
2. اضغط زر **المشاركة** (المربع والسهم لفوق).
3. اختار **Add to Home Screen** → **Add**.
4. هتلاقي الأيقونة على الشاشة الرئيسية.

✅ **النتيجة:** تطبيق موبايل بأيقونة، بيفتح ملء الشاشة، بواجهة متجاوبة (responsive) اتصممت للموبايل، ويشتغل أوفلاين.

---

## 📱 الطريقة 2: بناء ملف `.apk` أصلي لأندرويد (Capacitor)

لو الدكتور طالب **ملف APK فعلي**، استخدم **Capacitor** اللي بيغلّف تطبيق الويب في تطبيق أندرويد أصلي.

### المتطلبات
- **Node.js** — [https://nodejs.org](https://nodejs.org)
- **Android Studio** — [https://developer.android.com/studio](https://developer.android.com/studio) (بيجيب معاه Android SDK و JDK)

### الخطوات
افتح PowerShell في فولدر المشروع:

```powershell
# 1) جهّز مشروع Node وثبّت Capacitor
npm init -y
npm install @capacitor/core @capacitor/cli @capacitor/android

# 2) هيّئ Capacitor (خليه يقرأ ملفات الويب من الفولدر الحالي)
npx cap init "CyberShield AI" "com.cybershield.ai" --web-dir="."

# 3) أضف منصة أندرويد
npx cap add android

# 4) انسخ ملفات الويب داخل مشروع أندرويد
npx cap copy

# 5) افتح المشروع في Android Studio
npx cap open android
```

### داخل Android Studio
1. استنى لحد ما يخلّص **Gradle sync**.
2. من القائمة: **Build → Build Bundle(s) / APK(s) → Build APK(s)**.
3. لما يخلص، اضغط **locate** → هتلاقي ملف **`app-debug.apk`**.
4. انقل الملف للموبايل وثبّته (فعّل "تثبيت من مصادر غير معروفة").

> ملف `capacitor.config.json` جاهز موجود في المشروع كمرجع للإعدادات (اسم التطبيق و الـ App ID).

---

## 🧭 أنهي طريقة أستخدم؟

| | الطريقة 1 (PWA) | الطريقة 2 (APK) |
|---|---|---|
| السرعة | ⚡ دقايق | تحتاج Android Studio |
| النتيجة | أيقونة + ملء الشاشة | ملف `.apk` حقيقي |
| أدوات | مفيش (بس رفع على النت) | Node + Android Studio |
| مناسبة لـ | البريزنتيشن السريع | تسليم ملف تطبيق |

**نصيحة:** للبريزنتيشن استخدم الطريقة 1 (PWA) — سريعة ومبهرة. لو مطلوب APK للتسليم، خصّص وقت للطريقة 2 لأن تحميل Android Studio كبير.

---

## 🆘 حل المشاكل

| المشكلة | الحل |
|---------|------|
| مفيش "Add to Home screen" | لازم يكون عبر HTTPS (Netlify/GitHub Pages)، مش IP محلي |
| على iPhone مش شغال | لازم تستخدم **Safari** بالتحديد (مش Chrome) |
| الأيقونة مش ظاهرة صح | تأكد إن فولدر `assets/` اترفع مع باقي الملفات |
| Gradle sync فشل | افتح Android Studio مرة تانية وسيبه يحمّل مكوّنات SDK الناقصة |

---

## 🧪 تجربة سريعة على الموبايل بدون رفع (نفس الشبكة)

لو عايز تجرّب بسرعة والموبايل على نفس شبكة الواي فاي:
1. على الكمبيوتر شغّل: `powershell -ExecutionPolicy Bypass -File serve.ps1`
2. اعرف IP الكمبيوتر: اكتب `ipconfig` وشوف `IPv4 Address` (مثلاً `192.168.1.5`).
3. على الموبايل افتح: `http://192.168.1.5:8080`

> ملاحظة: عبر IP محلي (مش HTTPS) التطبيق هيفتح ويشتغل، بس خاصية **"التثبيت"** بتحتاج HTTPS، فللتثبيت الفعلي استخدم Netlify/GitHub Pages.
