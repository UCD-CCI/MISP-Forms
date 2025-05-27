function showFields() {
    var incidentType = document.getElementById("incidentType").value;
    var fieldMappings = {
        "phishing": "phishingFields",
        "smishing": "smishingFields",
        "ddos": "ddosFields",
        "malware": "malwareFields",
        "sqlInject": "sqlInjectFields"
    };

    // Hide all fields first
    Object.values(fieldMappings).forEach(fieldId => {
        document.getElementById(fieldId).style.display = "none";
    });

    // Show only the selected field
    if (fieldMappings[incidentType]) {
        document.getElementById(fieldMappings[incidentType]).style.display = "block";
    }
}

function setTodayDate() {
    var today = new Date().toISOString().slice(0, 10);
    var dateFields = ["phishingDate", "smishingDate", "ddosDate", "malwareDate", "sqlInjectDate"];

    dateFields.forEach(fieldId => {
        let field = document.getElementById(fieldId);
        if (field) field.value = today;
    });
}

// Ensure functions are globally accessible
window.showFields = showFields;
window.setTodayDate = setTodayDate;

document.addEventListener("DOMContentLoaded", function () {
    function showSpinner() {
        let spinner = document.getElementById('loading-spinner');
        if (spinner) spinner.style.display = 'block';
    }

    function updateTLPBackground(selectElement) {
        const bgColorMap = {
            "TLP:RED": "#ffcccc",   // Light red
            "TLP:AMBER": "#fff4cc", // Light amber
            "TLP:GREEN": "#ccffcc", // Light green
            "TLP:WHITE": "#ffffff"  // White
        };
        selectElement.style.backgroundColor = bgColorMap[selectElement.value] || "#ffffff";
    }

    // Set default TLP background color and add event listener
    const tlpSelect = document.getElementById('tlp');
    if (tlpSelect) {
        updateTLPBackground(tlpSelect);
        tlpSelect.addEventListener("change", function () {
            updateTLPBackground(this);
        });
    }

    // Expose functions globally
    window.showSpinner = showSpinner;
    window.updateTLPBackground = updateTLPBackground;
});

document.addEventListener("DOMContentLoaded", function () {
    document.querySelector("form").addEventListener("submit", function (event) {
        let sourceIpInput = document.getElementById("source_ip").value;
        let targetIpInput = document.getElementById("target_ip").value;
        let emailInput = document.getElementById("email") ? document.getElementById("email").value : "";
        let phoneInput = document.getElementById("phone") ? document.getElementById("phone").value : "";

        let sourceIps = sourceIpInput.split(",").map(ip => ip.trim());
        let targetIp = targetIpInput.trim();

        let ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+:+)+[a-fA-F0-9]+$/;
        let emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        let phoneRegex = /^\+?[0-9]{7,15}$/;

        // Validate Source IPs
        for (let ip of sourceIps) {
            if (!ipRegex.test(ip)) {
                alert("Invalid Source IP: " + ip);
                event.preventDefault();
                return;
            }
        }

        // Validate Target IP
        if (!ipRegex.test(targetIp)) {
            alert("Invalid Target IP: " + targetIp);
            event.preventDefault();
            return;
        }

        // Validate Email (if present)
        if (emailInput.trim() !== "" && !emailRegex.test(emailInput)) {
            alert("Invalid Email Address: " + emailInput);
            event.preventDefault();
            return;
        }

        // Validate Phone Number (if present)
        if (phoneInput.trim() !== "" && !phoneRegex.test(phoneInput)) {
            alert("Invalid Phone Number: " + phoneInput);
            event.preventDefault();
            return;
        }

        // If all validation passes, show spinner
        showSpinner();
    });
});
