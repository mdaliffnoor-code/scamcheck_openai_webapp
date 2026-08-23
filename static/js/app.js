document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.tab');
    const panels = document.querySelectorAll('.tab-panel');
    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            tabs.forEach((item) => item.classList.remove('active'));
            panels.forEach((panel) => panel.classList.remove('active'));
            tab.classList.add('active');
            const target = document.getElementById(tab.dataset.target);
            if (target) target.classList.add('active');
        });
    });
    const fileInput = document.getElementById('file-input');
    const fileName = document.getElementById('file-name');
    if (fileInput && fileName) {
        fileInput.addEventListener('change', () => {
            fileName.textContent = fileInput.files.length ? fileInput.files[0].name : 'No file selected';
        });
    }
});

setTimeout(function () {
    const flashMessages = document.querySelectorAll('.flash');

    flashMessages.forEach(function (message) {
        message.classList.add('flash-fade');

        setTimeout(function () {
            message.remove();
        }, 500);
    });
}, 2000);

document.addEventListener('DOMContentLoaded', function () {

    const modal = document.getElementById('auth-required-modal');
    const closeButton = document.getElementById('auth-required-close');
    const protectedForms = document.querySelectorAll('.login-required-form');

    if (!modal) {
        return;
    }

    protectedForms.forEach(function (form) {

        form.addEventListener('submit', function (event) {

            event.preventDefault();

            modal.classList.add('show');

        });

    });


    if (closeButton) {

        closeButton.addEventListener('click', function () {
            modal.classList.remove('show');
        });

    }


    modal.addEventListener('click', function (event) {

        if (event.target === modal) {
            modal.classList.remove('show');
        }

    });


    document.addEventListener('keydown', function (event) {

        if (event.key === 'Escape') {
            modal.classList.remove('show');
        }

    });

});

// =========================================
// PREVIOUS BULLETINS DROPDOWN
// =========================================

document.addEventListener("DOMContentLoaded", function () {

    const toggle =
        document.getElementById("previousBulletinsToggle");

    const menu =
        document.getElementById("previousBulletinsMenu");


    if (!toggle || !menu) {
        return;
    }


    toggle.addEventListener("click", function () {

        menu.classList.toggle("active");

    });

});
