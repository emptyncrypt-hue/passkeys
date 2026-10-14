import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app.component';

describe('AppComponent', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({ imports: [AppComponent], providers: [provideHttpClient()] }).compileComponents();
  });
  it('renders passkey actions and a status', () => {
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('h1')?.textContent).toContain('Passkeys Demo');
    expect(root.querySelectorAll('button').length).toBe(3);
    expect(root.querySelector('[role=status]')?.textContent).toContain('Not authenticated');
  });
});
