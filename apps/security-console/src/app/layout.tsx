import "./globals.css";
import { jetbrainsMono } from "./fonts";

export const metadata = {
  title: "Cindertrace",
  description: "Security investigations and response",
};

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`dark ${jetbrainsMono.variable}`}>
      <body className="min-h-screen bg-bg text-text antialiased">{children}</body>
    </html>
  );
}
