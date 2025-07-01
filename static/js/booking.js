document.addEventListener('DOMContentLoaded', function() {
    // Initialize date picker
    flatpickr("#date", {
        minDate: "today",
        dateFormat: "Y-m-d"
    });

    // Initialize time picker
    flatpickr("#time", {
        enableTime: true,
        noCalendar: true,
        dateFormat: "H:i",
        minTime: "09:00",
        maxTime: "21:00"
    });

    // Calculate total price
    function calculatePrice() {
        const duration = parseInt(document.getElementById('duration').value);
        const basePrice = 2000; // Base price per hour
        const totalPrice = basePrice * duration;
        document.getElementById('totalPrice').textContent = `¥${totalPrice.toLocaleString()}`;
    }

    document.getElementById('duration').addEventListener('change', calculatePrice);
    calculatePrice(); // Initial calculation
});