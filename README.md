# Security Blog

A modern, performant technical blog built with Astro for sharing in-depth articles about cryptography, reverse engineering, security vulnerabilities, and secure communication protocols.

## 🚀 Features

- ✨ **Modern Design** - Clean, professional interface with smooth dark/light mode
- 🎨 **Tailwind CSS** - Fully responsive and customizable styling
- 📝 **MDX Support** - Write articles with Markdown and interactive components
- 🎯 **Code Highlighting** - Beautiful syntax highlighting with Shiki
- 🏷️ **Tag System** - Filter articles by topics (cryptography, reverse-engineering, etc.)
- 📅 **Archive Page** - Browse articles organized by year and month
- 🔍 **SEO Optimized** - Meta tags, Open Graph, sitemap, and RSS feed
- ⚡ **Lightning Fast** - Static site generation for optimal performance
- 🌙 **Dark Mode** - System preference detection with manual toggle
- 📱 **Mobile Friendly** - Fully responsive design

## 🛠️ Tech Stack

- **Framework**: [Astro 4.x](https://astro.build)
- **Styling**: [Tailwind CSS](https://tailwindcss.com)
- **Content**: MDX with frontmatter
- **TypeScript**: Full type safety
- **Syntax Highlighting**: Shiki (built into Astro)

## 📦 Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd blog

# Install dependencies
npm install

# Start development server
npm run dev
```

The site will be available at `http://localhost:4321/`

## 📁 Project Structure

```
/
├── public/              # Static assets (images, favicon, etc.)
├── src/
│   ├── components/      # Reusable components
│   │   ├── Header.astro
│   │   ├── Footer.astro
│   │   └── ArticleCard.astro
│   ├── content/         # Blog posts
│   │   ├── config.ts    # Content collection schema
│   │   └── blog/        # Article markdown files
│   │       ├── cryptography-basics.md
│   │       ├── android-drm-analysis.md
│   │       └── tls-vulnerabilities.md
│   ├── layouts/         # Page layouts
│   │   ├── BaseLayout.astro
│   │   └── BlogPost.astro
│   ├── pages/           # Routes
│   │   ├── index.astro       # Homepage
│   │   ├── about.astro       # About page
│   │   ├── archive.astro     # Archive page
│   │   ├── blog/
│   │   │   ├── index.astro   # Blog listing
│   │   │   └── [slug].astro  # Individual post
│   │   └── rss.xml.ts        # RSS feed
│   └── styles/          # Global styles
│       └── global.css
├── astro.config.mjs     # Astro configuration
├── tailwind.config.mjs  # Tailwind configuration
└── tsconfig.json        # TypeScript configuration
```

## ✍️ Writing Articles

### Creating a New Article

1. Create a new `.md` or `.mdx` file in `src/content/blog/`
2. Add frontmatter with required fields
3. Write your content using Markdown

### Article Frontmatter

```markdown
---
title: "Your Article Title"
description: "A brief description of your article"
pubDate: 2024-01-15
updatedDate: 2024-01-20  # Optional
author: "Mamoun Tarsha-Kurdi"
tags: ["cryptography", "security", "reverse-engineering"]
draft: false
---

Your article content here...
```

### Frontmatter Fields

- **title** (required): Article title
- **description** (required): Short description for SEO and previews
- **pubDate** (required): Publication date (YYYY-MM-DD format)
- **updatedDate** (optional): Last update date
- **author** (optional): Author name (defaults to "Mamoun Tarsha-Kurdi")
- **tags** (optional): Array of topic tags
- **draft** (optional): Set to `true` to hide from production (defaults to `false`)

### 📅 Changing Article Dates

To change when an article appears in the timeline:

1. Open the article's markdown file in `src/content/blog/`
2. Modify the `pubDate` field in the frontmatter:

```markdown
---
title: "My Article"
pubDate: 2024-02-20  # Change this date
updatedDate: 2024-02-25  # Optional: add when you update the content
---
```

The blog will automatically:
- Sort articles by the `pubDate` (newest first)
- Display the publication date on article cards and pages
- Organize articles in the archive page by year/month
- Show "Last updated" if `updatedDate` is present

### Code Blocks

Use standard Markdown code blocks with syntax highlighting:

````markdown
```python
def encrypt_data(key, plaintext):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag
```
````

#### Line Highlighting

Highlight specific lines by adding `{line-numbers}` after the language:

````markdown
```python {3,5-7}
def vulnerable_function():
    # This line is normal
    password = "hardcoded"  # Highlighted line
    
    # These lines are highlighted
    if password == user_input:
        grant_access()
```
````

### Tags

Common tags used in this blog:
- `cryptography` - Encryption, hashing, cryptographic protocols
- `reverse-engineering` - Binary analysis, decompilation, DRM
- `security` - General security topics
- `vulnerabilities` - Security flaws and exploits
- `protocols` - TLS/SSL, network protocols
- `android` - Android app security
- `windows` - Windows application security
- `linux` - Linux security

## 🎨 Customization

### Colors

Edit `tailwind.config.mjs` to change the color scheme:

```javascript
theme: {
  extend: {
    colors: {
      primary: {
        // Change these values
        500: '#0ea5e9',
        600: '#0284c7',
        // ...
      },
    },
  },
},
```

### Dark Mode

The theme is automatically detected from system preferences. Users can toggle it manually using the button in the header.

### Site Information

Update site information in `astro.config.mjs`:

```javascript
export default defineConfig({
  site: 'https://yourdomain.com',  // Your actual domain
  // ...
});
```

## 🚀 Deployment

### Build for Production

```bash
npm run build
```

This generates a static site in the `dist/` directory.

### Deploy to Netlify

1. Push your code to GitHub
2. Connect your repository to Netlify
3. Build settings:
   - Build command: `npm run build`
   - Publish directory: `dist`

### Deploy to Vercel

```bash
npm i -g vercel
vercel
```

### Deploy to GitHub Pages

1. Update `astro.config.mjs`:
```javascript
export default defineConfig({
  site: 'https://username.github.io',
  base: '/repository-name',  // If not using root
});
```

2. Build and deploy:
```bash
npm run build
# Deploy the dist/ folder to gh-pages branch
```

## 📊 SEO Features

- ✅ Semantic HTML structure
- ✅ Meta tags (title, description)
- ✅ Open Graph tags (social media sharing)
- ✅ Twitter Card tags
- ✅ Canonical URLs
- ✅ Sitemap generation (`/sitemap-index.xml`)
- ✅ RSS feed (`/rss.xml`)
- ✅ Robots.txt support

## 🔧 Available Commands

```bash
# Development
npm run dev          # Start dev server at localhost:4321

# Production
npm run build        # Build for production
npm run preview      # Preview production build

# Maintenance
npm run astro --      # Run Astro CLI commands
```

## 📝 Content Guidelines

For technical security articles:

1. **Be Detailed**: Include code examples and technical explanations
2. **Show, Don't Tell**: Use working code snippets
3. **Responsible Disclosure**: Include ethical disclaimers
4. **Stay Current**: Update articles when information changes (use `updatedDate`)
5. **Use Tags**: Properly categorize articles for discoverability

## 🤝 Contributing

Feel free to submit issues or pull requests to improve the blog!

## 📄 License

MIT License - feel free to use this template for your own blog.

## 🙏 Acknowledgments

- Built with [Astro](https://astro.build)
- Styled with [Tailwind CSS](https://tailwindcss.com)
- Syntax highlighting by [Shiki](https://shiki.matsu.io)
- Icons from [Heroicons](https://heroicons.com)

---

**Happy blogging!** 🚀
