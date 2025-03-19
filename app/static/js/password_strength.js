function checkPasswordStrength(password) {
    const strengthBar = document.getElementById("strength-bar");
    const strengthText = document.getElementById("strength-text");
    let strength = 0;

    
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength++;

    
    strengthBar.value = strength;
    const messages = [
        "Bardzo słabe",
        "Słabe",
        "Średnie",
        "Dobre",
        "Bardzo dobre",
        "Świetne"
    ];
    strengthText.textContent = messages[strength];
    strengthText.style.color = strength >= 4 ? "green" : "red";
}
