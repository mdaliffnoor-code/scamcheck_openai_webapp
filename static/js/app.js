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

// =========================================
// ADMIN SCAN ACTIVITY FILTERING
// =========================================

document.addEventListener("DOMContentLoaded", function () {

    const userFilter =
        document.getElementById("filterUser");

    const typeFilter =
        document.getElementById("filterScanType");

    const riskFilter =
        document.getElementById("filterRisk");

    const dateSort =
        document.getElementById("sortDate");

    const tableBody =
        document.getElementById("activityTableBody");


    if (!tableBody) {
        return;
    }


    function updateTable() {

        const rows = Array.from(
            tableBody.querySelectorAll("tr")
        );


        const userValue =
            userFilter
                ? userFilter.value
                    .toLowerCase()
                    .trim()
                : "";

        const typeValue =
            typeFilter
                ? typeFilter.value.toLowerCase()
                : "";

        const riskValue =
            riskFilter
                ? riskFilter.value
                : "";


        // FILTER ROWS

        rows.forEach(function (row) {

            const rowUser =
                row.dataset.user || "";

            const rowType =
                row.dataset.type || "";

            const rowRisk =
                row.dataset.risk || "";


            const userMatches =
                !userValue
                || rowUser.includes(userValue);

            const typeMatches =
                !typeValue
                || rowType === typeValue;

            const riskMatches =
                !riskValue
                || rowRisk === riskValue;


            if (
                userMatches
                && typeMatches
                && riskMatches
            ) {

                row.style.display = "";

            } else {

                row.style.display = "none";

            }

        });


        // SORT DATE

        rows.sort(function (a, b) {

            const dateA =
                Number(a.dataset.date);

            const dateB =
                Number(b.dataset.date);


            if (
                dateSort
                && dateSort.value === "earliest"
            ) {

                return dateA - dateB;

            }

            // DEFAULT:
            // LATEST → EARLIEST

            return dateB - dateA;

        });


        rows.forEach(function (row) {

            tableBody.appendChild(row);

        });

    }


    if (userFilter) {

        userFilter.addEventListener(
            "input",
            updateTable
        );

    }


    if (typeFilter) {

        typeFilter.addEventListener(
            "change",
            updateTable
        );

    }


    if (riskFilter) {

        riskFilter.addEventListener(
            "change",
            updateTable
        );

    }


    if (dateSort) {

        dateSort.addEventListener(
            "change",
            updateTable
        );

    }


    // Apply default sorting when page loads

    updateTable();

});
