# CUSTOM AT

    at-custom/
    ├── server.js           Server (backend chung cho cả 2 web)
    ├── web-nguoi-choi/     WEB NGƯỜI CHƠI  -> mở ở  /
    │   └── index.html
    ├── web-admin/          WEB ADMIN       -> mở ở  /admin  (cần mật khẩu)
    │   └── index.html
    └── data/               (tự tạo) dữ liệu đội + ảnh logo/bill — giữ lại khi deploy

Chạy (Node 22+, không cần npm install):

    PORT=3000 node server.js

Mật khẩu admin mặc định là 226. Muốn đổi: đặt biến ADMIN_PASSWORD khi chạy.
