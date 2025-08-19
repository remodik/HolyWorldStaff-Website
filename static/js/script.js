document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                window.scrollTo({
                    top: target.offsetTop - 80,
                    behavior: 'smooth'
                });
            }
        });
    });

    const editForms = document.querySelectorAll('.edit-guide-form');
    editForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const content = this.querySelector('textarea[name="content"]').value.trim();
            if (!content) {
                e.preventDefault();
                alert('Содержание не может быть пустым!');
            }
        });
    });

    const contentEditor = document.getElementById('content');
    if (contentEditor) {
        const preview = document.getElementById('preview');
        if (preview) {
            contentEditor.addEventListener('input', function() {
                preview.innerHTML = this.value;
            });
        }
    }
});

function confirmDelete() {
    return confirm('Вы уверены, что хотите удалить этот элемент? Это действие нельзя отменить.');
}